# Copyright 2020 DeChainy
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import shutil
import signal
from dataclasses import dataclass, field
from multiprocessing import Queue
from typing import ClassVar, List, Type

from dechainy.ebpf import SwapStateCompile
from dechainy.plugins import Probe

from .utility import AnalysisState, MyManager, HookModulesConfig, RunState
from .detection_engine import BaseEngine, DebugEngine, FullEngine
from .traffic_analyser import BaseAnalyser, EbpfFullAnalyser, EbpfPerfAnalyser, SocketAnalyser, SimulatedAnalyser
from .analysis_adjuster import AnalysisAdjuster


# TODO: Model e Features devono essere trovati in maniera dinamica
@dataclass
class Efads(Probe):
    operational_modes: ClassVar[List] = [
        "simulated", "socket", "full_ebpf", "filtered_ebpf"]
    
    run_state: RunState = field(default_factory=RunState)
    analysis_state: AnalysisState = field(default_factory=AnalysisState)

    ta_proc: Type[BaseAnalyser] = None
    de_proc: Type[BaseEngine] = None
    aa_proc: Type[AnalysisAdjuster] = None
    
    def __post_init__(self):
        if self.run_state.operational_mode not in Efads.operational_modes:
            raise Exception("Operational Mode incorrect or missing")

        if self.run_state.operational_mode == "simulated" and not self.run_state.debug or not self.run_state.debug.pcaps:
            raise Exception("Need pcaps for the simulations")
        
        base_dir = os.path.dirname(__file__)
        shutil.copyfile(os.path.join(base_dir, 'ebpf_{}.c'.format(
            self.analysis_state.extraction_type)), os.path.join(base_dir, 'ebpf.c'))

        if not self.ingress.required:
            self.ingress.required = True

        for hook in ['ingress', 'egress']:
            chook = getattr(self, hook)
            if chook.required:
                chook.cflags = self.cflags_from_state()
        
        self.run_state.interface = self.interface
        self.run_state.mode = self.mode
        self.run_state.main_pid = os.getpid()
        super().__post_init__(path=__file__)

    def cflags_from_state(self):
        return [
            '-DSESSION_PER_TIME_WINDOW={}'.format(
                self.analysis_state.sessions_per_time_window),
            '-DTIME_WINDOW={}'.format(self.analysis_state.time_window),
            '-DTEST_{}=1'.format(self.run_state.operational_mode.upper()),
            '-DMAX_BLOCKED_SESSIONS={}'.format(
                self.analysis_state.max_blocked_sessions),
            '-DPACKETS_PER_SESSION={}'.format(
                self.analysis_state.packets_per_session)
        ] + ['-D{}=1'.format(x.upper()) for x in self.analysis_state.features]

    def post_compilation(self):
        self.manager = MyManager()
        self.manager.start()
        
        for htype in ['ingress', 'egress']:
            p = self[htype]
            hook: HookModulesConfig = getattr(self.analysis_state, htype)
            if not p:
                continue
            hook.module_fd = p.bpf.module
            if isinstance(p, SwapStateCompile):
                hook.module_swap_fd = p.bpf_1.module                
            hook.program_id = p.program_id
            hook.bpf_features = p.features

        shared_conf = self.manager.AnalysisState(**self.analysis_state.__dict__)
        packets_queue = Queue()
        
        if self.run_state.operational_mode == 'simulated':
            self.de_proc = SimulatedAnalyser(shared_conf, packets_queue, self.run_state)
        elif self.run_state.operational_mode == 'socket':
            self.de_proc = SocketAnalyser(shared_conf, packets_queue, self.run_state)
        elif self.run_state.operational_mode == 'full_ebpf':
            self.de_proc = EbpfFullAnalyser(shared_conf, packets_queue, self.run_state)
        elif self.run_state.operational_mode == 'filtered_ebpf':
            self.de_proc = EbpfPerfAnalyser(shared_conf, packets_queue, self.run_state)
        
        if self.run_state.debug:
            self.ta_proc = DebugEngine(shared_conf, packets_queue, self.run_state)
        else:
            self.ta_proc = FullEngine(shared_conf, packets_queue, self.run_state)
        
        if self.run_state.operational_mode != 'simulated':
            self.aa_proc = AnalysisAdjuster(shared_conf, self.run_state)
        
        if self.de_proc:
            self.de_proc.start()
        
        if self.ta_proc:
            self.ta_proc.start()
            
        if self.aa_proc:
            self.aa_proc.start()

        self.shared_conf = shared_conf
        self.on_update()

    def on_update(self):
        self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})

    def __del__(self):
        self.manager.shutdown()
        if self.de_proc:
            try:
                os.kill(self.de_proc.pid, signal.SIGTERM)
            except Exception:
                pass
            self.de_proc = None
        if self.ta_proc:
            try:
                os.kill(self.ta_proc.pid, signal.SIGTERM)
            except Exception:
                pass
            self.ta_proc = None
        if self.aa_proc:
            try:
                os.kill(self.aa_proc.pid, signal.SIGTERM)
            except Exception:
                pass
            self.aa_proc = None
        p = self['ingress']
        p["BLACKLISTED_IPS"].clear()
        p.bpf["PACKET_COUNTER"].clear()
        p.bpf["SESSIONS_TRACKED_DDOS"].clear()
        
        try:
            [x for x in p.bpf["PACKET_BUFFER_DDOS"].values()]
        except Exception:
            pass
        
        if isinstance(p, SwapStateCompile):
            p.bpf_1["SESSIONS_TRACKED_DDOS_1"].clear()
            try:
                [x for x in p.bpf_1["PACKET_BUFFER_DDOS_1"].values()]    
            except Exception:
                pass
        super().__del__()
