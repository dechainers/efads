import ctypes as ct
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

from .utility import AnalysisState, MyProxy, RunState, SessionValue, Checkpoint, _keys_map, get_ordered_key
from .detection_engine import DetectionEngine
from .analysis_adjuster import AnalysisAdjuster, Action
from .policy_enforcer import PolicyEnforcer


class BaseAnalyser:
    def __init__(self, efads):
        from . import Efads
        self.de = DetectionEngine()
        self.aa = AnalysisAdjuster(efads.run_state.debug.dump_file, attackers=efads.run_state.debug.attackers)
        self.pe = PolicyEnforcer()
        self.run_state: RunState = efads.run_state
        self.target: Union[MyProxy, weakref.ReferenceType[Efads]
                           ] = efads.shared_conf if efads.run_state.daemon else weakref.ref(efads)
        self.session_map: Dict[Tuple, SessionValue] = {}
        self.checkpoints: List[Checkpoint] = []
    
    def on_update(self):
        self.analysis_state: AnalysisState = self.target.__deepcopy__(
            {}) if self.run_state.daemon else self.target().analysis_state
        self.p = self.analysis_state.reconstruct_programs(self.run_state.mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]
        self.de.on_update(self.analysis_state)
        self.aa.on_update(
            self.analysis_state.keys_cost, self.analysis_state.keys_size,
            self.analysis_state.features_cost, self.analysis_state.features_size)

    def _trigger_read(self):
        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()
            
    def _extract_blackmap(self):
        return {tuple([getattr(k, n) for n in _keys_map.keys()])
                           : v for k, v in self.blacklist_map.items_lookup_batch()}  

    def _terminate_timewindow(self):
        self.checkpoints.append(Checkpoint("begin", time.time_ns()))
        self._trigger_read()
        self.checkpoints.append(Checkpoint("controls", time.time_ns()))
        black_map = self._extract_blackmap()
        self.checkpoints.append(Checkpoint("blackmap", time.time_ns()))
        cnt = self.p['ingress']["COUNTERS"][0].value
        self.p['ingress']["COUNTERS"].clear()
        self.checkpoints.append(Checkpoint("packetmap", time.time_ns()))
        packets_dict = self.session_map.copy()
        self.session_map.clear()
        self.checkpoints.append(Checkpoint("sessionmap", time.time_ns()))
        predictions = self.de.predict(packets_dict, self.checkpoints)
        self.pe.enforce(self.p, predictions, packets_dict, self.checkpoints)
        res = self.aa.adjust(packets_dict, cnt, black_map, self.checkpoints)
        if res != Action.STEADY:
            print("Devi fare cose")
        self.checkpoints.clear()
        

    @abstractclassmethod
    def start():
        pass


class SimulatedAnalyser(BaseAnalyser):
    def start(self):
        self.on_update()
        for pcap_file in self.run_state.debug.pcaps:
            start_time_window = -1
            for i, (ts, buf) in enumerate(ppcap.Reader(filename=pcap_file)):
                if i == 0:
                    start_time_window = ts

                # start_time_window is used to group packets/flows captured in a time-window
                if ts > start_time_window + (self.analysis_state.time_window * 10**9):
                    start_time_window = ts
                    self._terminate_timewindow()

                eth = ethernet.Ethernet(buf)
                if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None and eth[ip.IP, udp.UDP] is None and eth[ip.IP, icmp.ICMP] is None):
                    continue

                self.p['ingress']["COUNTERS", True][0] = ct.c_uint64(
                    self.p['ingress']["COUNTERS", True][0].value + 1)
                sess_id = get_ordered_key([y[0](eth)
                                           for y in _keys_map.values()])

                key = self.blacklist_map.Key()
                [setattr(key, n, sess_id[j]) for j, n in enumerate(
                    _keys_map.keys())]

                if key in self.blacklist_map:
                    self.blacklist_map[key] = ct.c_ulong(
                        self.blacklist_map[key].value + 1)
                    continue

                if sess_id not in self.session_map:
                    if len(self.session_map) >= self.analysis_state.sessions_per_time_window:
                        self.session_map[sess_id] = SessionValue(tot_pkts=1, is_tracked=False)
                        continue
                    self.session_map[sess_id] = SessionValue(tot_pkts=0, is_tracked=True)
                    self.p['ingress']["COUNTERS", True][1] = ct.c_uint64(
                        self.p['ingress']["COUNTERS", True][1].value + 1)
                self.session_map[sess_id].tot_pkts += 1

                if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                    continue
                self.session_map[sess_id].pkts.append(
                    [y[0](eth) for y in self.analysis_state.features.values()])
            if self.session_map:
                self._terminate_timewindow()
            print(f"Finito {pcap_file}")


class SocketAnalyser(BaseAnalyser):
    def _spawn_thread(self):
        t = threading.Timer(
            self.analysis_state.time_window, self._terminate_timewindow)
        t.daemon = True
        t.start()

    def start(self):
        self.on_update()

        # If the interface is in promiscuous then here all packets are seen
        psock = psocket.SocketHndl(
            iface_name=self.run_state.interface, timeout=self.run_state.timeout)
        self._spawn_thread()
        for raw_bytes in psock:
            eth = ethernet.Ethernet(raw_bytes)
            if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None and eth[ip.IP, udp.UDP] is None and eth[ip.IP, icmp.ICMP] is None):
                continue

            sess_id = get_ordered_key([y[0](eth) for y in _keys_map.values()])

            if sess_id not in self.session_map:
                if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                    continue
                self.session_map[sess_id] = SessionValue()
            self.session_map[sess_id].tot_pkts += 1

            if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                continue

            self.session_map[sess_id].pkts.append(
                [y[0](eth) for y in self.analysis_state.features.values()])
        psock.close()

    def _terminate_timewindow(self):
        super()._terminate_timewindow
        self._spawn_thread()


class EbpfFullAnalyser(BaseAnalyser):
    def start(self):
        while not self.stopped:
            time.sleep(self.analysis_state.time_window)
            self.checkpoints.append(time.time_ns())
            self._trigger_read()
            self._extract_sessions(self.p['ingress']["SESSIONS_TRACKED_DDOS"])
            self.checkpoints.append(time.time_ns())
            self.p['ingress']["COUNTERS"].clear()
            self._extract_packets(self.p['ingress']["PACKET_BUFFER_DDOS"])
            self.checkpoints.append(time.time_ns())
            self._terminate_timewindow()

    def _extract_packets(self, queue):
        for p in queue.values():
            sess_id = tuple([getattr(p.id, x) for x in _keys_map.keys()])
            features = [getattr(p, x) for x in self.analysis_state.features]
            if sess_id not in self.session_map:
                print("ERRORIRNO")
            self.session_map[sess_id].pkts.append(features)

    def _extract_sessions(self, table):
        self.session_map = {tuple([getattr(k, x) for x in _keys_map.keys()]): SessionValue(tot_pkts=v) for k, v in table.items_lookup_and_delete_batch()}


class EbpfPerfAnalyser(EbpfFullAnalyser, SocketAnalyser):
    def start(self):
        self.on_update()
        self.p['ingress']['CUSTOM_TO_CP'].open_perf_buffer(self._handle_packet)
        self._spawn_thread()
        while True:
            self.p['ingress'].bpf.perf_buffer_poll()

    def _handle_packet(self, cpu, data, size):
        converted = self.p['ingress']['CUSTOM_TO_CP'].event(data)
        sess_id = tuple([getattr(converted.id, x) for x in _keys_map.keys()])
        features = [getattr(converted, x) for x in self.analysis_state.features]
        if sess_id not in self.session_map:
            self.session_map[sess_id] = []
        self.session_map[sess_id].append(features)


class WithProcess(Process):
    def __init__(self, analyser: Type[BaseAnalyser]):
        Process.__init__(self)
        self.daemon = True
        self.analyser = analyser

    def run(self):
        self.analyser.start()
        os.kill(os.getppid(), signal.SIGUSR1)