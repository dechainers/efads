import ctypes as ct
import dataclasses
import json
import math
import os
import random
import signal
import time
from abc import abstractclassmethod
from base64 import b64decode
from multiprocessing import Process

import numpy as np
from dechainy.utility import cint_type_limit

from .utility import AnalysisState, GlobalResultManager, RunState, _keys_map


class BaseEngine(Process):
    def __init__(self, shared_conf, shared_queue, run_state):
        Process.__init__(self)
        self.daemon = True
        self.shared_queue = shared_queue
        self.shared_conf = shared_conf
        self.run_state: RunState = run_state

    def on_update(self):
        self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})
        self.p = self.analysis_state.reconstruct_programs(
            self.run_state.main_pid, self.run_state.mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]

        # feature list with min and max values (None has to be set at runtime)
        feature_list = [cint_type_limit(
            x[1]) for x in self.analysis_state.features.values()]
        # adjust time_window max value in features
        if "timestamp" in self.analysis_state.features:
            feature_list[0] = (feature_list[0][0],
                               self.analysis_state.time_window)

        self.maxs = np.array([x[1] for x in feature_list])
        self.rng = np.array([x[1] - x[0] for x in feature_list])

        self.model = self.analysis_state.model_name
        if not os.path.isfile(self.model):
            content = self.model
            self.model = "/tmp/model"
            with open(self.model, "wb+") as fp:
                fp.write(b64decode(content))

        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
        import tensorflow as tf
        SEED = 1

        # Seed Random Numbers
        os.environ['PYTHONHASHSEED'] = str(SEED)
        np.random.seed(SEED)
        random.seed(SEED)

        tf.random.set_seed(SEED)
        tf.keras.backend.set_image_data_format('channels_last')

        # load now the model, when sure to be in a different process
        self.model = tf.keras.models.load_model(self.model)

        # warmup
        for _ in range(10):
            self.model.predict(np.expand_dims(np.array([
                self.normalize_and_padding_sample(np.array([[random.randint(
                    0, 10) for _ in range(len(self.analysis_state.features))]], dtype=float)),
            ]), axis=3), batch_size=self.analysis_state.batch_size)

    def normalize_and_padding_sample(self, sample, high: float = 1.0, low: float = 0.0):
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > self.analysis_state.packets_per_session:
            sample = sample[:self.analysis_state.packets_per_session, ...]
        if "timestamp" in self.analysis_state.features:
            sample[:, 0] = (sample[:, 0] - sample[0][0]) / 1000000000
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (self.maxs - sample)) / self.rng)
        # padding
        return np.pad(norm_sample, ((
            0, self.analysis_state.packets_per_session - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))

    def run(self):
        self.on_update()
        self.additional_parse = self.parse_ebpf if 'ebpf' in self.analysis_state.extraction_type else lambda x: x
        self.loop()

    def parse_ebpf(self, packets_raw):
        session_map = {}
        feature_decl = self.p["PACKET_BUFFER_DDOS"].Leaf
        for raw in packets_raw:
            skb_event = ct.cast(raw, ct.POINTER(feature_decl)).contents
            sess_id = tuple([getattr(skb_event.id, x)
                             for x in _keys_map.keys()])
            features = [getattr(skb_event, x)
                        for x in self.analysis_state.features]
            if sess_id not in session_map:
                session_map[sess_id] = []
            session_map[sess_id].append(features)
        return session_map

    @abstractclassmethod
    def loop(self):
        pass


class DebugEngine(BaseEngine):
    def loop(self):
        self.max_timewindows_empty = self.run_state.debug.n_timewindows_empty or float(
            "inf")
        self.max_timewindows = math.ceil(self.run_state.debug.max_duration /
                                         self.shared_conf.time_window) if self.run_state.debug.max_duration else float("inf")
        self.results = GlobalResultManager(
            attackers=self.run_state.debug.attackers)
        self.n_timewindows_empty = 0

        if os.path.isfile(self.run_state.debug.dump_file):
            os.remove(self.run_state.debug.dump_file)

        while True:
            val = self.shared_queue.get()
            # TODO: IMPLEMENTA MESSAGGI
            while val is True:
                self.shared_queue.put(val)
                time.sleep(1)
                val = self.shared_queue.get()
            self.perform_prediction(*val)

    def perform_prediction(self, sess_map_or_packets, pkts_received, black_map, checkpoints):
        predictions, data, has_new_blocked = [], [], False

        # stop if no data sent
        if not checkpoints:
            with open(self.run_state.debug.dump_file, "w") as fp:
                json.dump(dataclasses.asdict(self.results), fp, indent=2)
            os.kill(os.getppid(), signal.SIGUSR1)
            return

        if not sess_map_or_packets:
            checkpoints += [time.time_ns()] * 4
        else:
            checkpoints.append(time.time_ns())
            sess_map_or_packets = self.additional_parse(sess_map_or_packets)
            for v in sess_map_or_packets.values():
                data.append(self.normalize_and_padding_sample(
                    np.array(v.pkts, dtype=float)))
            data = np.array(data)
            data = np.expand_dims(data, axis=3)
            checkpoints.append(time.time_ns())
            predictions = np.squeeze(self.model.predict(
                data, batch_size=self.analysis_state.batch_size), axis=1)
            checkpoints.append(time.time_ns())
            for i, p in zip(sess_map_or_packets, predictions):
                if p <= 0.5:
                    continue
                key = self.blacklist_map.Key()
                [setattr(key, n, i[j]) for j, n in enumerate(_keys_map.keys())]
                if key not in self.blacklist_map:
                    has_new_blocked = True
                    self.blacklist_map[key] = ct.c_ulong(0)
            checkpoints.append(time.time_ns())

        self.results.end_tw(predictions, sess_map_or_packets,
                            pkts_received, black_map, checkpoints)
        self.n_timewindows_empty = 0 if has_new_blocked else self.n_timewindows_empty + 1

        if self.run_state.operational_mode == "simulated" and len(self.results.time_window_values) % 2 == 0:
            self.shared_queue.put(True)

        # stop if reached the maximum treshold
        if self.n_timewindows_empty == self.max_timewindows_empty or len(self.results.time_window_values) == self.max_timewindows:
            with open(self.run_state.debug.dump_file, "w") as fp:
                json.dump(dataclasses.asdict(self.results), fp, indent=2)
            os.kill(os.getppid(), signal.SIGUSR1)


class FullEngine(BaseEngine):

    def loop(self):
        self.on_update()
        while True:
            val = self.shared_queue.get()
            # TODO: IMPLEMENTA MESSAGGI
            self.perform_prediction(*val)

    def perform_prediction(self, sess_map_or_packets):
        predictions, data = [], []

        if not sess_map_or_packets:
            return

        sess_map_or_packets = self.additional_parse(sess_map_or_packets)
        for v in sess_map_or_packets.values():
            data.append(self.normalize_and_padding_sample(
                np.array(v.pkts, dtype=float)))
        data = np.array(data)
        data = np.expand_dims(data, axis=3)
        predictions = np.squeeze(self.model.predict(
            data, batch_size=self.analysis_state.batch_size), axis=1)
        for i, p in zip(sess_map_or_packets, predictions):
            if p <= 0.5:
                continue
            key = self.blacklist_map.Key()
            [setattr(key, n, i[j]) for j, n in enumerate(_keys_map.keys())]
            if key not in self.blacklist_map:
                self.blacklist_map[key] = ct.c_ulong(0)
