import os
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing.managers import BaseManager, NamespaceProxy
from typing import Union

from dechainy.ebpf import BPF, MetricFeatures, Program, SwapStateCompile

from efads_simulator.utility import *


class OperationalMode(Enum):
    SOCKET = "socket"
    EBPF = "ebpf"
    FILTERED_EBPF = "filtered_ebpf"


class SafeProgram(Program):
    def __del__(self):
        os.close(self.f.fd)
        super().__del__()


class SafeSwap(SwapStateCompile):
    def __del__(self):
        os.close(self.f_1.fd)
        super().__del__()


@dataclass
class HookModulesConfig:
    module_fd: int = -1
    module_swap_fd: int = -1
    program_id: int = -1
    bpf_features: MetricFeatures = field(default_factory=MetricFeatures)


@dataclass
class LiveDebugConfiguration(DebugConfiguration):
    max_duration: int = 300
    top_frequence: float = 0.1


@dataclass
class RunState(RunState):
    daemon: bool = False
    operational_mode: Union[str, OperationalMode] = OperationalMode.EBPF
    debug: LiveDebugConfiguration = field(default_factory=LiveDebugConfiguration)

    def __post_init__(self):
        if isinstance(self.operational_mode, str):
            self.operational_mode = OperationalMode(self.operational_mode)


@dataclass
class LiveAnalysisState(AnalysisState):
    ingress: HookModulesConfig = field(
        default_factory=HookModulesConfig)
    egress: HookModulesConfig = field(
        default_factory=HookModulesConfig)

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
        return "{}({})".format(LiveAnalysisState.__name__, ", ".join(
            ["{}={}".format(x, getattr(self, x))
             for x, y in LiveAnalysisState.__dataclass_fields__.items()]
        ))


class MyManager(BaseManager):
    def start(self):
        self.register("AnalysisState", LiveAnalysisState, MyProxy)
        return super().start()
