import ctypes as ct
import os
import random
import time
from abc import abstractclassmethod
from base64 import b64decode

import numpy as np
from dechainy.utility import cint_type_limit

from .utility import RunState, _keys_map


os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import tensorflow as tf
SEED = 1
# Seed Random Numbers
os.environ['PYTHONHASHSEED'] = str(SEED)
np.random.seed(SEED)
random.seed(SEED)
tf.random.set_seed(SEED)
tf.keras.backend.set_image_data_format('channels_last')

        

class BaseEngine:
    def __init__(self, run_state):
        self.run_state: RunState = run_state

    def __del__(self):
        if hasattr(self, "model"):
            del self.model
        tf.keras.backend.clear_session()

    def on_update(self, analysis_state):
        self.analysis_state = analysis_state
        self.additional_parse = self.parse_ebpf if 'ebpf' in self.analysis_state.extraction_type else lambda x: x
        
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

        tf.keras.backend.clear_session()
        # load now the model, when sure to be in a different process
        self.model = tf.keras.models.load_model(self.model)

        # warmup
        for _ in range(10):
            self.model.predict(np.expand_dims(np.array([
                self.normalize_and_padding_sample(np.array([[random.randint(
                    0, 10) for _ in range(analysis_state.active_features)]], dtype=float)),
            ]), axis=3), batch_size=analysis_state.batch_size)

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
    def handle_extraction(self):
        pass


class DebugEngine(BaseEngine):
    def handle_extraction(self, sess_map_or_packets):
        predictions, data, checkpoints = [], [], []

        if not sess_map_or_packets:
            return [time.time_ns()] * 4
        
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
        checkpoints.append(time.time_ns())

        return predictions, sess_map_or_packets, checkpoints


class FullEngine(BaseEngine):
    
    def handle_extraction(self, sess_map_or_packets):
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
        return predictions
