import ctypes as ct
import json
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from threading import Thread, Event 
from multiprocessing.managers import BaseManager, NamespaceProxy
from typing import Dict, List, OrderedDict

from bcc import BPF
from dechainy.ebpf import MetricFeatures, Program, SwapStateCompile
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp


def get_saddr(x):
    return struct.unpack('<I', x[ip.IP].src)[0]


def get_daddr(x):
    return struct.unpack('<I', x[ip.IP].dst)[0]


def get_sport(x):
    return socket.htons(x[tcp.TCP].sport) if x[tcp.TCP] else socket.htons(x[udp.UDP].sport) if x[udp.UDP] else 0


def get_dport(x):
    return socket.htons(x[tcp.TCP].dport) if x[tcp.TCP] else socket.htons(x[udp.UDP].dport)


def get_proto(x):
    return x[ip.IP].p


def get_timestamp(x):
    return time.time_ns()


def get_ip_len(x):
    return x[ip.IP].len


def get_ip_flags(x):
    return x[ip.IP].flags


def get_tcp_len(x):
    return len(x[tcp.TCP].body_bytes) if x[tcp.TCP] else 0


def get_tcp_ack(x):
    return x[tcp.TCP].ack if x[tcp.TCP] else 0


def get_tcp_flags(x):
    return x[tcp.TCP].flags if x[tcp.TCP] else 0


def get_tcp_win(x):
    return x[tcp.TCP].win if x[tcp.TCP] else 0


def get_udp_len(x):
    return len(x[udp.UDP].body_bytes) if x[udp.UDP] else 0


def get_icmp_type(x):
    return x[icmp.ICMP].type if x[icmp.ICMP] else 0


_keys_map: Dict = OrderedDict([
    ("saddr", (get_saddr, ct.c_uint32)),
    ("daddr", (get_daddr, ct.c_uint16)),
    ("sport", (get_sport, ct.c_uint16)),
    ("dport", (get_dport, ct.c_uint16)),
    ("proto", (get_proto, ct.c_uint16)),
])

_features_map: Dict = {
    "perpacket": OrderedDict([
        ("timestamp", (get_timestamp, ct.c_uint64)),
        ("ip_len", (get_ip_len, ct.c_uint16)),
        ("ip_flags", (get_ip_flags, ct.c_uint16)),
        ("tcp_len", (get_tcp_len, ct.c_uint16)),
        ("tcp_ack", (get_tcp_ack, ct.c_uint32)),
        ("tcp_flags", (get_tcp_flags, ct.c_uint16)),
        ("tcp_win", (get_tcp_win, ct.c_uint16)),
        ("udp_len", (get_udp_len, ct.c_uint16)),
        ("icmp_type", (get_icmp_type, ct.c_uint8))
    ]),
    "aggregate": OrderedDict([])
}


@dataclass
class DebugConfiguration:
    attackers: Dict
    dump_file: str
    max_duration: int = 300
    n_timewindows_empty: int = 20
    pcaps: List[str] = field(default_factory=list)


@dataclass
class HookModulesConfig:
    module_fd: int = -1
    module_swap_fd: int = -1
    program_id: int = -1
    bpf_features: MetricFeatures = field(default_factory=MetricFeatures)


@dataclass
class RunState:
    interface: str = "lo"
    timeout: int = 1000000
    operational_mode: str = "simulated"
    debug: DebugConfiguration = None
    mode: int = BPF.SCHED_CLS
    daemon: bool = False


@dataclass
class ConsumptionState:
    os_cpu: int = 0
    os_mem: int = 0
    efads_cpu: int = 0
    efads_mem: int = 0
    
    def update(self):
        pass


@dataclass
class AnalysisState:
    extraction_type: str = "perpacket"
    
    sessions_per_time_window: int = 10000
    max_blocked_sessions: int = 100000
    time_window: int = 10
    
    packets_per_session: int = 10
    active_features: int = 9

    model_dir: str = None
    batch_size: int = 2048
    features: OrderedDict = field(default_factory=OrderedDict)

    ingress: HookModulesConfig = field(
        default_factory=HookModulesConfig)
    egress: HookModulesConfig = field(
        default_factory=HookModulesConfig)

    def __post_init__(self):
        weights_file = os.path.join(self.model_dir, "weights.json")
        if not os.path.isfile(weights_file):
            raise Exception("No weights file found")
        with open(weights_file, "r") as fp:
            weights = json.load(fp)
        
        if self.extraction_type == "perpacket":
            weights = weights[str(self.packets_per_session)][str(self.active_features)]
        else:
            weights = weights[str(self.active_features)]
            
        features_names = list(_features_map[self.extraction_type].keys())
        active_names = [features_names[i] for _, i in weights][:self.active_features]
        self.features = {k: v for k, v in _features_map[self.extraction_type].items() if k in active_names}
    
    @property
    def model_name(self):
        return os.path.join(self.model_dir, "{}p-{}f.h5".format(self.packets_per_session, self.active_features) if self.extraction_type == "perpacket" else "{}.h5".format(self.active_features))
    
    @property
    def features_size(self):
        return sum([ct.sizeof(v[1]) for k, v in self.features.items()])

    @property
    def keys_size(self):
        return sum([ct.sizeof(v[1]) for v in _keys_map.values()])
    
    def reconstruct_programs(self, mode: int):
        ret = {}
        for htype in ['ingress', 'egress']:
            ret[htype] = None
            hook: HookModulesConfig = getattr(self, htype)

            if hook.module_fd <= 0:
                continue

            if hook.module_swap_fd <= 0:
                p = Program(interface=None, idx=None, mode=mode, code='int internal_handler(){return 0;}',
                            cflags=[], probe_id=-1, plugin_id=-1, debug=False, flags=None, offload_device=None,
                            program_id=hook.program_id, features=hook.bpf_features)
                p.bpf.module = hook.module_fd
                p.bpf.cleanup = lambda: None
            else:
                p = SwapStateCompile(interface=None, idx=None, mode=mode, code='int internal_handler(){return 0;}',
                                     cflags=[], probe_id=-1, plugin_id=-1, debug=False, flags=None, offload_device=None,
                                     program_id=hook.program_id, code_1='int internal_handler(){return 0;}',
                                     chain_map='{}_next_{}'.format(
                                         htype, 'xdp' if mode == BPF.XDP else 'tc'), features=hook.bpf_features)
                p.bpf.module = hook.module_fd
                p.bpf_1.module = hook.module_swap_fd
                p.bpf.cleanup = lambda: None
                p.bpf_1.cleanup = lambda: None
            ret[htype] = p
        return ret


class MyProxy(NamespaceProxy):
    def __repr__(self) -> str:
        return "{}({})".format(AnalysisState.__name__, ", ".join(
            ["{}={}".format(x, getattr(self, x))
             for x, y in AnalysisState.__dataclass_fields__.items()]
        ))


class MyManager(BaseManager):
    def start(self):
        self.register("AnalysisState", AnalysisState, MyProxy)
        return super().start()


@dataclass
class SessionValue:
    tot_pkts: int = 0
    pkts: List = field(default_factory=list)

    @property
    def received_pkts(self):
        return len(self.pkts)

    @property
    def ignored_pkts(self):
        return self.tot_pkts - self.received_pkts


@dataclass
class InfoMetric:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    tp_pkts: int = 0
    fp_pkts: int = 0
    tn_pkts: int = 0
    fn_pkts: int = 0
    tp_no_space_pkts: int = 0
    fp_no_space_pkts: int = 0
    tn_no_space_pkts: int = 0
    fn_no_space_pkts: int = 0
    tp_mit_pkts: int = 0
    fp_mit_pkts: int = 0
    tn_mit_pkts: int = 0
    fn_mit_pkts: int = 0


@dataclass
class TimeWindowResultManager(ConsumptionState):
    unique: InfoMetric = field(default_factory=InfoMetric)
    general: InfoMetric = field(default_factory=InfoMetric)
    tp_other_mitigated: int = 0
    fp_other_mitigated: int = 0
    other_pkts_no_space: int = 0
    controls_time: int = 0
    extraction_time: int = 0
    queue_time: int = 0
    parse_time: int = 0
    prediction_time: int = 0
    blacklist_time: int = 0
    total_time: int = 0


@dataclass
class GlobalResultManager(TimeWindowResultManager):
    time_window_values: List[TimeWindowResultManager] = field(
        default_factory=list)
    attackers: List[List] = field(default_factory=list, repr=False)

    def __post_init__(self):
        self.seen_sess = {}
        self.real_malicious_len = len(self.attackers[0])
        self.real_malicious = dict.fromkeys(
            [tuple(x) for x in self.attackers], None)
        self.global_black_map = {}
        
    def get_black_map_tw(self, black_map):
        ret = {}
        for k in black_map.keys():
            if k not in self.seen_sess and k[:self.real_malicious_len] in self.real_malicious and k in self.global_black_map:
                print("ERRORINOOOOOOOOOOO")
            ret[k] = black_map[k] if k not in self.global_black_map else black_map[k]-self.global_black_map[k]
            if ret[k] == 0:
                del ret[k]
        self.global_black_map = black_map
        return ret
    
    def end_tw(self, predictions, packets_session_map, pkts_received, black_map, checkpoints):    
        tw_black_map = self.get_black_map_tw(black_map)
        tw_res = TimeWindowResultManager(
            controls_time=checkpoints[1] - checkpoints[0],
            extraction_time=checkpoints[2] - checkpoints[1],
            queue_time=checkpoints[3] - checkpoints[2],
            parse_time=checkpoints[4] - checkpoints[3],
            prediction_time=checkpoints[5] - checkpoints[4],
            blacklist_time=checkpoints[6] - checkpoints[5],
            total_time=checkpoints[6] - checkpoints[0]
        )

        for sess_id, pred in zip(packets_session_map, predictions):
            is_already_seen = sess_id in self.seen_sess
            is_malicious = sess_id[:self.real_malicious_len] in self.real_malicious
            is_predicted_malicious = pred > 0.5
            self.seen_sess[sess_id] = (self.seen_sess[sess_id] or is_predicted_malicious) if is_already_seen else is_predicted_malicious
            val: SessionValue = packets_session_map[sess_id]
            pkts_received -= val.ignored_pkts + val.received_pkts
            
            cond = {
                "tp": is_malicious and is_predicted_malicious,
                "fp": is_predicted_malicious and is_malicious != is_predicted_malicious,
                "tn": not is_predicted_malicious and not is_malicious,
                "fn": not is_predicted_malicious and is_malicious != is_predicted_malicious
            }

            for k, v in cond.items():
                if not v:
                    continue
                setattr(tw_res.general, k, getattr(tw_res.general, k)+1)
                setattr(tw_res.general, "{}_pkts".format(k), getattr(
                    tw_res.general, "{}_pkts".format(k))+val.received_pkts)
                setattr(tw_res.general, "{}_no_space_pkts".format(k), getattr(
                    tw_res.general, "{}_no_space_pkts".format(k))+val.ignored_pkts)
                
                if not is_already_seen:
                    setattr(tw_res.unique, k, getattr(tw_res.unique, k)+1)
                    setattr(tw_res.unique, "{}_pkts".format(k), getattr(
                        tw_res.unique, "{}_pkts".format(k))+val.received_pkts)
                    setattr(tw_res.unique, "{}_no_space_pkts".format(k), getattr(
                        tw_res.unique, "{}_no_space_pkts".format(k))+val.ignored_pkts)
                
                if sess_id in tw_black_map:
                    setattr(tw_res.general, "{}_mit_pkts".format(k), getattr(
                        tw_res.general, "{}_mit_pkts".format(k))+tw_black_map[sess_id])
                    if not is_already_seen:
                      setattr(tw_res.unique, "{}_mit_pkts".format(k), getattr(
                          tw_res.unique, "{}_mit_pkts".format(k))+tw_black_map[sess_id])
                    pkts_received -= tw_black_map[sess_id]
                    del tw_black_map[sess_id]
                
        for k,v in tw_black_map.items():
            if k not in self.seen_sess:
                print("ERRORE DELLA MADONNA")
            is_predicted_malicious = self.seen_sess[k]
            is_malicious = k[:self.real_malicious_len] in self.real_malicious
            if is_predicted_malicious and is_malicious != is_predicted_malicious:
                tw_res.fp_other_mitigated += v
            else:
                tw_res.tp_other_mitigated += v
            pkts_received -= v
            
        tw_res.other_pkts_no_space = pkts_received
        
        for k, v in tw_res.__dict__.items():
            kobj = getattr(tw_res, k)
            if isinstance(kobj, InfoMetric):
                mobj = getattr(self, k)
                for kk, vv in kobj.__dict__.items():
                    setattr(mobj, kk, vv + getattr(mobj, kk))
            else:
                setattr(self, k, v + getattr(self, k))

        self.time_window_values.append(tw_res)
