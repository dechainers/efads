import os
import signal
import time
from abc import abstractclassmethod
from multiprocessing import Process
from typing import Dict, Tuple, Type, Union, List
import weakref
import threading
from pypacker import ppcap, psocket
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp
from pypacker.layer12 import ethernet

from .utility import AnalysisState, ExtractionType, MyProxy, SessionValue, Checkpoint, _keys_map, get_ordered_key
from .detection_engine import DetectionEngine
from .analysis_adjuster import AnalysisAdjuster, Action, SimulatedAdjuster
from .policy_enforcer import PolicyEnforcer, SimulatedPolicyEnforcer


class SimulatedAnalyser:
    def __init__(self, run_state, analysis_state, pcaps):
        if not pcaps:
            raise Exception("Need pcaps for the simulation")
        self.pcaps = pcaps
        self.de = DetectionEngine()
        self.aa = SimulatedAdjuster(
            run_state.debug.dump_dir, run_state.debug.attackers)
        self.pe = SimulatedPolicyEnforcer()
        self.session_map: Dict[Tuple, SessionValue] = {}
        self.checkpoints: List[Checkpoint] = []
        self.analysis_state = analysis_state
        self.black_map = {}
        self.cnt = 0
        self.cnt_tracked = 0

    def on_update(self):
        self.de.on_update(
            self.analysis_state.features, self.analysis_state.extraction_type, self.analysis_state.time_window,
            self.analysis_state.model_name, self.analysis_state.packets_per_session, self.analysis_state.batch_size)
        self.aa.on_update(
            self.analysis_state.keys_cost, self.analysis_state.keys_size,
            self.analysis_state.features_cost, self.analysis_state.features_size,
            self.analysis_state.extraction_type)

    def _terminate_timewindow(self):
        self.checkpoints.append(Checkpoint("begin", time.time_ns()))
        self.checkpoints.append(Checkpoint("sessionmap", time.time_ns()))
        predictions = self.de.predict(self.session_map, self.checkpoints)
        self.pe.enforce(self.black_map, predictions,
                        self.session_map, self.checkpoints)
        res = self.aa.adjust(self.session_map, self.cnt,
                             self.black_map.copy(), self.checkpoints)
        self.cnt = 0
        self.cnt_tracked = 0
        self.session_map.clear()
        if res != Action.STEADY:
            raise NotImplementedError("Not implemented action")
        self.checkpoints.clear()

    def start(self):
        self.on_update()
        for pcap_file in self.pcaps:
            start_time_window = -1
            for i, (ts, buf) in enumerate(ppcap.Reader(filename=pcap_file)):
                if i == 0:
                    start_time_window = ts

                # start_time_window is used to group packets/flows captured in a time-window
                if ts > start_time_window + (self.analysis_state.time_window * 10**9):
                    start_time_window = ts
                    self._terminate_timewindow()

                eth = ethernet.Ethernet(buf)
                if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None
                                          and eth[ip.IP, udp.UDP] is None
                                          and eth[ip.IP, icmp.ICMP] is None):
                    continue

                self.cnt += 1
                sess_id = get_ordered_key([y[0](eth)
                                           for y in _keys_map.values()])

                if sess_id in self.black_map:
                    self.black_map[sess_id] += 1
                    continue

                if sess_id not in self.session_map:
                    if self.cnt_tracked >= self.analysis_state.sessions_per_time_window:
                        self.session_map[sess_id] = SessionValue(
                            tot_pkts=1, is_tracked=False)
                        continue
                    self.session_map[sess_id] = SessionValue(
                        tot_pkts=0, is_tracked=True)
                    self.cnt_tracked += 1
                self.session_map[sess_id].tot_pkts += 1

                if not self.session_map[sess_id].is_tracked:
                    continue

                if self.analysis_state.extraction_type == ExtractionType.PERPACKET:
                    if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                        continue
                    self.session_map[sess_id].pkts_or_counters.append(
                        [y[0](eth) for y in self.analysis_state.features.values()])
                else:
                    new_vals = [y[0](eth)
                                for y in self.analysis_state.features.values()]
                    if not self.session_map[sess_id].pkts_or_counters:
                        self.session_map[sess_id].pkts_or_counters = new_vals
                    else:
                        for i in range(len(new_vals)):
                            self.session_map[sess_id].pkts_or_counters[i] += new_vals[i]
            if self.session_map:
                self._terminate_timewindow()


class BaseAnalyser:
    def __init__(self, efads):
        from . import Efads
        self.de = DetectionEngine()
        self.aa = AnalysisAdjuster(efads.run_state.debug.dump_dir,
                                   efads.run_state.debug.attackers,
                                   efads.run_state.debug.max_duration,
                                   os.getppid() if efads.run_state.daemon else os.getpid(),
                                   efads.run_state.debug.top_frequence)
        self.pe = PolicyEnforcer()
        self.target: Union[MyProxy, weakref.ReferenceType[Efads]
                           ] = efads.shared_conf if efads.run_state.daemon else weakref.ref(efads)
        self.session_map: Dict[Tuple, SessionValue] = {}
        self.checkpoints: List[Checkpoint] = []
        self.run_mode: int = efads.mode

    @property
    def is_daemon(self):
        return not isinstance(self.target, weakref.ReferenceType)

    def on_update(self):
        self.analysis_state: AnalysisState = self.target.__deepcopy__(
            {}) if self.is_daemon else self.target().analysis_state
        self.p = self.analysis_state.reconstruct_programs(self.run_mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]
        self.de.on_update(
            self.analysis_state.features, self.analysis_state.extraction_type, self.analysis_state.time_window,
            self.analysis_state.model_name, self.analysis_state.packets_per_session, self.analysis_state.batch_size)
        self.aa.on_update(
            self.analysis_state.keys_cost, self.analysis_state.keys_size,
            self.analysis_state.features_cost, self.analysis_state.features_size,
            self.analysis_state.extraction_type)

    def _trigger_read(self):
        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()

    def _extract_blackmap(self):
        return {tuple([getattr(k, n) for n in _keys_map.keys()]): v for k, v in self.blacklist_map.items_lookup_batch()}

    def _terminate_timewindow(self, skip_trigger=False):
        if not skip_trigger:
            self.checkpoints.append(Checkpoint("begin", time.time_ns()))
            self._trigger_read()
            t = time.time_ns()
            self.checkpoints.append(Checkpoint("controls", t))
            self.checkpoints.append(Checkpoint("synchro_map", t))
        black_map = self._extract_blackmap()
        self.checkpoints.append(Checkpoint("blackmap", time.time_ns()))
        cnt = self.p['ingress']["COUNTERS"][0].value
        n_tracked = self.p['ingress']["COUNTERS"][1].value
        self.p['ingress']["COUNTERS"].clear()
        self.checkpoints.append(Checkpoint("packetmap", time.time_ns()))
        packets_dict = self.session_map.copy()
        self.session_map.clear()
        self.checkpoints.append(Checkpoint("sessionmap", time.time_ns()))
        predictions = self.de.predict(packets_dict, self.checkpoints)
        self.pe.enforce(self.p, predictions, packets_dict, self.checkpoints)
        res = self.aa.adjust(packets_dict, cnt, black_map,
                             n_tracked, self.checkpoints)
        if res != Action.STEADY:
            if res == Action.STOP:
                if self.is_daemon:
                    os.kill(os.getppid(), signal.SIGUSR1)
                    exit()
                else:
                    raise TimeoutError()
            else:
                raise NotImplementedError("Not implemented action")
        self.checkpoints.clear()

    @abstractclassmethod
    def start():
        pass


class SocketAnalyser(BaseAnalyser):
    def __init__(self, efads):
        super().__init__(efads)
        self.interface = efads.interface
        self.timeout = efads.run_conf.debug.timeout

    def _spawn_thread(self):
        t = threading.Timer(
            self.analysis_state.time_window, self._terminate_timewindow)
        t.daemon = True
        t.start()

    def start(self):
        self.on_update()

        # If the interface is in promiscuous then here all packets are seen
        psock = psocket.SocketHndl(
            iface_name=self.interface, timeout=self.timeout)
        self._spawn_thread()
        for raw_bytes in psock:
            eth = ethernet.Ethernet(raw_bytes)
            if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None
                                      and eth[ip.IP, udp.UDP] is None
                                      and eth[ip.IP, icmp.ICMP] is None):
                continue

            sess_id = get_ordered_key([y[0](eth) for y in _keys_map.values()])

            if sess_id not in self.session_map:
                if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                    continue
                self.session_map[sess_id] = SessionValue()
            self.session_map[sess_id].tot_pkts += 1

            if self.analysis_state.extraction_type == ExtractionType.PERPACKET:
                if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                    continue
                self.session_map[sess_id].pkts_or_counters.append(
                    [y[0](eth) for y in self.analysis_state.features.values()])
            else:
                new_vals = [y[0](eth)
                            for y in self.analysis_state.features.values()]
                if not self.session_map[sess_id].pkts_or_counters:
                    self.session_map[sess_id].pkts_or_counters = new_vals
                else:
                    for i in range(len(new_vals)):
                        self.session_map[sess_id].pkts_or_counters[i] += new_vals[i]
        psock.close()

    def _terminate_timewindow(self):
        super()._terminate_timewindow()
        self._spawn_thread()


class EbpfFullAnalyser(BaseAnalyser):
    def start(self):
        while True:
            time.sleep(self.analysis_state.time_window)
            self.checkpoints.append(Checkpoint("begin", time.time_ns()))
            self._trigger_read()
            self.checkpoints.append(Checkpoint("controls", time.time_ns()))
            self._extract_sessions(self.p['ingress']["SESSIONS_TRACKED_DDOS"])
            self.checkpoints.append(Checkpoint(
                "extract_sessions", time.time_ns()))
            self.p['ingress']["COUNTERS"].clear()
            if self.analysis_state.extraction_type == ExtractionType.PERPACKET:
                self._extract_packets(self.p['ingress']["PACKET_BUFFER_DDOS"])
                self.checkpoints.append(Checkpoint(
                    "extract_packets", time.time_ns()))
            self._terminate_timewindow(skip_trigger=True)

    def _extract_packets(self, queue):
        for p in queue.values():
            sess_id = tuple([getattr(p.id, x) for x in _keys_map.keys()])
            features = [getattr(p, x) for x in self.analysis_state.features]
            self.session_map[sess_id].pkts_or_counters.append(features)

    def _extract_sessions(self, table):
        for k, v in table.items_lookup_and_delete_batch():
            conv_key = tuple([getattr(k, x) for x in _keys_map.keys()])
            if conv_key not in self.session_map:
                self.session_map[conv_key] = SessionValue()
            self.session_map[conv_key].tot_pkts = v.pkts
            self.session_map[conv_key].is_tracked = v.is_tracked
            if self.analysis_state.extraction_type == ExtractionType.AGGREGATE:
                self.session_map[conv_key].pkts_or_counters = [
                    getattr(v.features, x) for x in self.analysis_state.features]


class EbpfPerfAnalyser(EbpfFullAnalyser):
    def start(self):
        self.on_update()
        self.p['ingress']['CUSTOM_TO_CP'].open_perf_buffer(self._handle_packet)
        self._spawn_thread()
        while True:
            self.p['ingress'].bpf.perf_buffer_poll()

    def _handle_packet(self, cpu, data, size):
        converted = self.p['ingress']['CUSTOM_TO_CP'].event(data)
        sess_id = tuple([getattr(converted.id, x) for x in _keys_map.keys()])
        features = [getattr(converted, x)
                    for x in self.analysis_state.features]
        if sess_id not in self.session_map:
            self.session_map[sess_id] = SessionValue()
        # here I assume it's perpacket
        self.session_map[sess_id].pkts_or_counters.append(features)

    def _spawn_thread(self):
        t = threading.Timer(
            self.analysis_state.time_window, self._terminate_timewindow)
        t.daemon = True
        t.start()

    def _terminate_timewindow(self):
        self.checkpoints.append(Checkpoint("begin", time.time_ns()))
        self._trigger_read()
        self.checkpoints.append(Checkpoint("controls", time.time_ns()))
        self._extract_sessions(self.p['ingress']["SESSIONS_TRACKED_DDOS"])
        self.checkpoints.append(Checkpoint("extract_sessions", time.time_ns()))
        self.p['ingress']["COUNTERS"].clear()
        super()._terminate_timewindow(skip_trigger=True)
        self._spawn_thread()


class WithProcess(Process):
    def __init__(self, analyser: Type[BaseAnalyser]):
        Process.__init__(self)
        self.daemon = True
        self.analyser = analyser

    def run(self):
        self.analyser.start()
        os.kill(os.getppid(), signal.SIGUSR1)
