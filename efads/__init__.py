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
import signal
from dataclasses import dataclass, field
from typing import Type, Union

from dechainy.ebpf import SwapStateCompile
from dechainy.plugins import Probe

from .utility import AnalysisState, MyManager, HookModulesConfig, OperationalMode, RunState
from .traffic_analyser import BaseAnalyser, EbpfFullAnalyser, EbpfPerfAnalyser, SocketAnalyser, WithProcess


# TODO: implementa in sotto classi le componenti async if needed
# TODO: implementa hook per registrare o eliminare definizioni di features
@dataclass
class Efads(Probe):
    run_state: RunState = field(default_factory=RunState)
    analysis_state: AnalysisState = field(default_factory=AnalysisState)
    proc: Union[Type[BaseAnalyser], WithProcess] = None

    def __post_init__(self):
        if not self.egress.required:
            self.ingress.required = True

        for hook in ['ingress', 'egress']:
            chook = getattr(self, hook)
            if chook.required:
                chook.cflags = self.cflags_from_state()

        super().__post_init__(path=__file__)

    def cflags_from_state(self):
        return [
            '-D{}=1'.format(self.analysis_state.extraction_type.value.upper()),
            '-DSESSION_PER_TIME_WINDOW={}'.format(
                self.analysis_state.sessions_per_time_window),
            '-DSESSION_PER_TIME_WINDOW_MAP={}'.format(
                self.analysis_state.sessions_per_time_window_map),
            '-DTIME_WINDOW={}'.format(self.analysis_state.time_window),
            '-DTEST_{}=1'.format(self.run_state.operational_mode.value.upper()),
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

        if self.run_state.operational_mode == OperationalMode.SOCKET:
            analyser = SocketAnalyser(self)
        elif self.run_state.operational_mode == OperationalMode.EBPF:
            analyser = EbpfFullAnalyser(self)
        elif self.run_state.operational_mode == OperationalMode.FILTERED_EBPF:
            analyser = EbpfPerfAnalyser(self)

        if not self.run_state.daemon:
            self.proc = analyser
            return

        self.manager = MyManager()
        self.manager.start()

        shared_conf = self.manager.AnalysisState(
            **self.analysis_state.__dict__)

        if self.run_state.daemon:
            self.proc = WithProcess(analyser)

        self.shared_conf = shared_conf
        self.proc.start()

    def update_analysis(self, analysis_state):
        # TODO: implement signaling
        # self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})
        pass

    def start(self):
        try:
            if self.run_state.daemon:
                signal.signal(signal.SIGUSR1, lambda _: None)
                signal.pause()
            else:
                self.proc.start()
        except TimeoutError:
            pass
        finally:
            self._logger.info("Finished the test")

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
