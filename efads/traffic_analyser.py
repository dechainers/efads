import ctypes as ct
import os
import signal
import time
from abc import abstractclassmethod
from multiprocessing import Process
from typing import Dict, Type, Union
import weakref
from pypacker import ppcap, psocket
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp
from pypacker.layer12 import ethernet

from .utility import AnalysisState, MyProxy, RunState, SessionValue, _keys_map
from .detection_engine import DebugEngine
from .analysis_adjuster import AnalysisAdjuster
from .policy_enforcer import PolicyEnforcer


class BaseAnalyser:
    def __init__(self, efads):
        from . import Efads
        self.de = DebugEngine(efads.run_state)
        self.aa = AnalysisAdjuster(efads.run_state.debug.attackers, efads.run_state.debug.dump_file)
        self.pe = PolicyEnforcer()
        self.run_state: RunState = efads.run_state
        self.target: Union[MyProxy, weakref.ReferenceType[Efads]] = efads.shared_conf if efads.run_state.daemon else weakref.ref(efads)
        
    def on_update(self):
        self.analysis_state: AnalysisState = self.target.__deepcopy__({}) if self.run_state.daemon else self.target().analysis_state
        self.p = self.analysis_state.reconstruct_programs(self.run_state.mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]
        self.features_size = self.analysis_state.features_size
        self.de.on_update(self.analysis_state)
    
    @abstractclassmethod
    def start():
        pass
    

class WithProcess(Process):
    def __init__(self, analyser: Type[BaseAnalyser]):
        Process.__init__(self)
        self.daemon = True
        self.analyser = analyser
    
    def run(self):
        self.analyser.start()
        os.kill(os.getppid(), signal.SIGUSR1)

    
class SimulatedAnalyser(BaseAnalyser):        
    def start(self):
        self.session_map: Dict[str, SessionValue] = {}
        self.on_update()
        for pcap_file in self.run_state.debug.pcaps:
            cnt = 0
            start_time_window = -1
            for i, (ts, buf) in enumerate(ppcap.Reader(filename=pcap_file)):
                if i == 0:
                    start_time_window = ts

                # start_time_window is used to group packets/flows captured in a time-window
                if ts > start_time_window + (self.analysis_state.time_window * 10**9):
                    start_time_window = ts
                    self.terminate_timewindow(cnt)

                eth = ethernet.Ethernet(buf)
                if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None and eth[ip.IP, udp.UDP] is None and eth[ip.IP, icmp.ICMP] is None):
                    continue
                
                cnt += 1
                sess_id = [y[0](eth) for y in _keys_map.values()]
                # lowest IP goes first in the identifier, to facilitate grouping packets
                if sess_id[1] < sess_id[0]:
                    sess_id = [sess_id[1], sess_id[0],
                               sess_id[3], sess_id[2], sess_id[4]]

                key = self.blacklist_map.Key()
                [setattr(key, n, sess_id[j]) for j, n in enumerate(
                    _keys_map.keys())]

                if key in self.blacklist_map:
                    self.blacklist_map[key] = ct.c_ulong(
                        self.blacklist_map[key].value + 1)
                    continue

                sess_id = tuple(sess_id)
                if sess_id not in self.session_map:
                    if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                        continue
                    self.session_map[sess_id] = SessionValue()
                self.session_map[sess_id].tot_pkts += 1

                if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                    continue
                self.session_map[sess_id].pkts.append(
                    [y[0](eth) for y in self.analysis_state.features.values()])
            if self.session_map:
                self.terminate_timewindow(cnt)
            print(f"Finito {pcap_file}")

    def terminate_timewindow(self, cnt):
        checkpoint_0 = time.time_ns()

        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()
        checkpoint_1 = time.time_ns()
        black_map = {tuple([getattr(k, n) for n in _keys_map.keys()]) : v for k, v in self.blacklist_map.items_lookup_batch()}
        self.p['ingress']["PACKET_COUNTER"].clear()
        tmp = self.session_map.copy()
        self.session_map.clear()
        checkpoint_2 = time.time_ns()
        predictions, sess_map_or_packets, checkpoints = self.de.handle_extraction(tmp)
        self.aa.handle(self.p, predictions, sess_map_or_packets, cnt, black_map, [checkpoint_0, checkpoint_1, checkpoint_2]+checkpoints)
        self.pe.handle(self.p['ingress']['BLACKLISTED_IPS'], predictions, sess_map_or_packets)
        
