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
from typing import ClassVar, List, Type, Union

from dechainy.ebpf import SwapStateCompile
from dechainy.plugins import Probe

from .utility import AnalysisState, MyManager, HookModulesConfig, RunState
from .traffic_analyser import BaseAnalyser, SimulatedAnalyser, WithProcess


# TODO: implementa in sotto classi le componenti async if needed
# TODO: implementa hook per registrare o eliminare definizioni di features
@dataclass
class Efads(Probe):
    operational_modes: ClassVar[List] = [
        "simulated", "socket", "full_ebpf", "filtered_ebpf"]

    run_state: RunState = field(default_factory=RunState)
    analysis_state: AnalysisState = field(default_factory=AnalysisState)

    proc: Union[Type[BaseAnalyser], WithProcess] = None

    def __post_init__(self):
        if self.run_state.operational_mode not in Efads.operational_modes:
            raise Exception("Operational Mode incorrect or missing")

        if self.run_state.operational_mode == "simulated":
            if not self.run_state.debug:
                raise Exception("For the simulation a debug config is needed")
            if not self.run_state.debug.pcaps:
                raise Exception("Need pcaps for the simulations")
            self.run_state.daemon = False

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
        super().__post_init__(path=__file__)

    def cflags_from_state(self):
        return [
            '-DSESSION_PER_TIME_WINDOW={}'.format(
                self.analysis_state.sessions_per_time_window),
            '-DSESSION_PER_TIME_WINDOW_MAP={}'.format(
                self.analysis_state.sessions_per_time_window if self.run_state.operational_mode ==
                "simulated" else self.analysis_state.max_blocked_sessions),
            '-DTIME_WINDOW={}'.format(self.analysis_state.time_window),
            '-DTEST_{}=1'.format(self.run_state.operational_mode.upper()),
            '-DMAX_BLOCKED_SESSIONS={}'.format(
                self.analysis_state.max_blocked_sessions),
            '-DPACKETS_PER_SESSION={}'.format(
                self.analysis_state.packets_per_session)
        ] + ['-D{}=1'.format(x.upper()) for x in self.analysis_state.features]

    def post_compilation(self):
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

        aa = SimulatedAnalyser(self)
        if not self.run_state.daemon:
            self.proc = aa
            return

        self.manager = MyManager()
        self.manager.start()

        shared_conf = self.manager.AnalysisState(
            **self.analysis_state.__dict__)

        if self.run_state.operational_mode == 'simulated':
            self.proc = WithProcess(aa)
        else:
            raise Exception()

        self.shared_conf = shared_conf
        self.proc.start()

    def update_analysis(self, analysis_state):
        # TODO: implement signaling
        #self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})
        pass

    def start(self):
        if self.run_state.daemon:
            signal.signal(signal.SIGUSR1, lambda _: None)
            signal.pause()
        else:
            self.proc.start()

    def __del__(self):
        try:
            self.manager.shutdown()
            del self.manager
        except Exception:
            pass
        try:
            if isinstance(self.proc, WithProcess):
                os.kill(self.proc.pid, signal.SIGTERM)
            del self.proc
        except Exception:
            pass
        super().__del__()
