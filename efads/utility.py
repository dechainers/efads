import ctypes as ct
import json
import os
import socket
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing.managers import BaseManager, NamespaceProxy
from typing import Dict, List, OrderedDict, Union

from bcc import BPF
from dechainy.ebpf import MetricFeatures, Program, SwapStateCompile
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp


def cint_type_limit(c_int_type):
    signed = c_int_type(-1).value < c_int_type(0).value
    bit_size = ct.sizeof(c_int_type) * 8
    signed_limit = 2 ** (bit_size - 1)
    return (-signed_limit, signed_limit - 1) if signed else (0, 2 * signed_limit - 1)


def get_ordered_key(sess_id):
    # lowest IP goes first in the identifier, to facilitate grouping packets
    if sess_id[1] < sess_id[0]:
        sess_id = [sess_id[1], sess_id[0], sess_id[3], sess_id[2], sess_id[4]]
    return tuple(sess_id)


def get_saddr(x):
    return struct.unpack('<I', x[ip.IP].src)[0]


def get_daddr(x):
    return struct.unpack('<I', x[ip.IP].dst)[0]


def get_sport(x):
    return socket.htons(x[tcp.TCP].sport) if x[tcp.TCP] else socket.htons(x[udp.UDP].sport) if x[udp.UDP] else 0


def get_dport(x):
    return socket.htons(x[tcp.TCP].dport) if x[tcp.TCP] else socket.htons(x[udp.UDP].dport) if x[udp.UDP] else 0


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
    ("saddr", (get_saddr, ct.c_uint32, 1)),
    ("daddr", (get_daddr, ct.c_uint32, 1)),
    ("sport", (get_sport, ct.c_uint16, 1)),
    ("dport", (get_dport, ct.c_uint16, 1)),
    ("proto", (get_proto, ct.c_uint8, 1)),
])

_features_map: OrderedDict([
    ("timestamp", (get_timestamp, ct.c_uint64, 5)),
    ("ip_len", (get_ip_len, ct.c_uint16, 1)),
    ("ip_flags", (get_ip_flags, ct.c_uint16, 1)),
    ("tcp_len", (get_tcp_len, ct.c_uint16, 1)),
    ("tcp_ack", (get_tcp_ack, ct.c_uint32, 1)),
    ("tcp_flags", (get_tcp_flags, ct.c_uint16, 1)),
    ("tcp_win", (get_tcp_win, ct.c_uint16, 1)),
    ("udp_len", (get_udp_len, ct.c_uint16, 1)),
    ("icmp_type", (get_icmp_type, ct.c_uint8, 1))
])


@dataclass
class HookModulesConfig:
    module_fd: int = -1
    module_swap_fd: int = -1
    program_id: int = -1
    bpf_features: MetricFeatures = field(default_factory=MetricFeatures)


@dataclass
class Checkpoint:
    name: str
    value: int


class OperationalMode(Enum):
    SIMULATED = "simulated"
    SOCKET = "socket"
    EBPF = "ebpf"
    FILTERED_EBPF = "filtered_ebpf"


class ExtractionType(Enum):
    PERPACKET = "perpacket"
    AGGREGATE = "aggregate"


class Costs(Enum):
    L4_COST = 10
    BLACKLIST_LOOKUP_COST = 1
    SPACE_LOOKUP_COST = 1
    KEY_INSERTION_COST = 2
    STORE_PACKET_COST = 2


@dataclass
class DebugConfiguration:
    attackers: Dict
    dump_dir: str
    max_duration: int = 300
    top_frequence: float = 0.1


@dataclass
class RunState:
    daemon: bool = False
    operational_mode: Union[str, OperationalMode] = OperationalMode.SIMULATED
    debug: DebugConfiguration = field(default_factory=DebugConfiguration)

    def __post_init__(self):
        if isinstance(self.operational_mode, str):
            self.operational_mode = OperationalMode(self.operational_mode)
        if self.operational_mode == OperationalMode.SIMULATED:
            self.daemon = False


@dataclass
class ConsumptionState:
    os_cpu: int = 0
    os_mem: int = 0


class SafeProgram(Program):
    def __del__(self):
        os.close(self.f.fd)
        super().__del__()


class SafeSwap(SwapStateCompile):
    def __del__(self):
        os.close(self.f_1.fd)
        super().__del__()


@dataclass
class AnalysisState:
    extraction_type: ExtractionType = ExtractionType.PERPACKET

    sessions_per_time_window: int = 10000
    sessions_per_time_window_map: int = 10000
    max_blocked_sessions: int = 100000
    time_window: float = 10

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
        if isinstance(self.extraction_type, str):
            self.extraction_type = ExtractionType(self.extraction_type)
        if self.sessions_per_time_window_map < self.sessions_per_time_window:
            self.sessions_per_time_window_map = self.sessions_per_time_window
        weights_file = os.path.join(self.model_dir, "weights.json")
        if not os.path.isfile(weights_file):
            raise Exception("No weights file found")
        with open(weights_file, "r") as fp:
            weights = json.load(fp)

        if self.extraction_type == ExtractionType.PERPACKET:
            weights = weights[str(self.packets_per_session)
                              ][str(self.active_features)]
        else:
            weights = weights[str(self.active_features)]

        features_names = list(_features_map.keys())
        active_names = [features_names[i]
                        for _, i in weights][:self.active_features]
        self.features = {
            k: v for k, v in _features_map.items() if k in active_names}

    @property
    def model_name(self):
        return os.path.join(self.model_dir, "{}p-{}f.h5".format(self.packets_per_session, self.active_features)
                            if self.extraction_type == ExtractionType.PERPACKET else "{}.h5".format(self.active_features))

    @property
    def features_size(self):
        return sum([ct.sizeof(v[1]) for v in self.features.values()])

    @property
    def features_cost(self):
        return sum([v[2] for v in self.features.values()])

    @property
    def keys_size(self):
        return sum([ct.sizeof(v[1]) for v in _keys_map.values()])

    @property
    def keys_cost(self):
        return sum([v[2] for v in _keys_map.values()]) +\
            Costs.L4_COST.value if "sport" in _keys_map or "dport" in _keys_map else 0

    def reconstruct_programs(self, mode: int):
        ret = {}
        for htype in ['ingress', 'egress']:
            ret[htype] = None
            hook: HookModulesConfig = getattr(self, htype)

            if hook.module_fd <= 0:
                continue

            if hook.module_swap_fd <= 0:
                p = SafeProgram(interface=None, idx=None, mode=mode, code='int internal_handler(){return 0;}',
                                cflags=[], probe_id=-1, plugin_id=-1, debug=False, flags=None, offload_device=None,
                                program_id=hook.program_id, features=hook.bpf_features)
                p.bpf.module = hook.module_fd
                p.bpf.cleanup = lambda: None
            else:
                p = SafeSwap(interface=None, idx=None, mode=mode, code='int internal_handler(){return 0;}',
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
    is_tracked: bool = False
    is_predicted_malicious: bool = False
    is_enforced: bool = False
    pkts_or_counters: List = field(default_factory=list)        


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
    tp_mit: int = 0
    fp_mit: int = 0
    tp_mit_pkts: int = 0
    fp_mit_pkts: int = 0
    other_tp_pkts_no_space: int = 0
    other_tn_pkts_no_space: int = 0
    other_pkts_no_space: int = 0


@dataclass
class TimeWindowResultManager:
    consumptions: ConsumptionState = field(default_factory=ConsumptionState)
    metrics: InfoMetric = field(default_factory=InfoMetric)
    times: Dict[str, int] = field(default_factory=dict)


@dataclass
class GlobalResultManager(TimeWindowResultManager):
    time_window_values: List[TimeWindowResultManager] = field(
        default_factory=list)
