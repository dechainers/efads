import importlib
import os
import signal
import time
import weakref
from abc import ABC, abstractclassmethod
from multiprocessing import Process
from typing import Dict, List, Tuple, Type, Union

from ..detection_engine import DetectionEngine
from ..analysis_adjuster import Action, LiveAnalysisAdjuster

from ..utility import LiveAnalysisState, MyProxy
from ..policy_enforcer import LivePolicyEnforcer
from ..utility import *


class BaseLiveAnalyser(ABC):
    def __init__(self, efads):
        from .. import Efads
        self.de: Type[DetectionEngine] = getattr(importlib.import_module('efads_simulator.detection_engine.{}'.format(efads.analysis_state.detection_engine_name)), efads.analysis_state.detection_engine_name.capitalize())(models_dir)
        self.aa = LiveAnalysisAdjuster(efads.run_state.debug.dump_dir,
                               efads.run_state.debug.attackers,
                               efads.run_state.debug.max_duration,
                               os.getpid(),
                               efads.run_state.debug.top_frequence)
        self.pe = LivePolicyEnforcer()
        self.target: Union[MyProxy, weakref.ReferenceType[Efads]
                           ] = efads.shared_conf if efads.run_state.daemon else weakref.ref(efads)
        self.session_map: Dict[Tuple, SessionValue] = {}
        self.checkpoints: List[Checkpoint] = []
        self.run_mode: int = efads.mode
        self.analysis_state: LiveAnalysisState = None

    @property
    def is_daemon(self):
        return not isinstance(self.target, weakref.ReferenceType)

    def broadcast_new_analysis(self):
        if self.is_daemon:
            pass # TODO: implement signal to update
        else:
            self.target().receive_new_analysis(self.analysis_state)
    
    def receive_new_analysis(self):
        if self.is_daemon:
            self.analysis_state = self.target.__deepcopy__({})
        else:
            self.analysis_state = self.target().analysis_state

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
    def start(self):
        self.p = self.analysis_state.reconstruct_programs(self.run_mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]
        ret = self.de.init(
            self.analysis_state.features, self.analysis_state.time_window,
            self.analysis_state.model_name, self.analysis_state.packets_per_session, self.analysis_state.batch_size)
        
        self.aa.init(
            self.analysis_state.keys_cost, self.analysis_state.keys_size,
            self.analysis_state.features_cost, self.analysis_state.features_size,
            self.analysis_state.extraction_type)


class WithProcess(Process):
    def __init__(self, analyser: Type[BaseLiveAnalyser]):
        Process.__init__(self)
        self.daemon = True
        self.analyser = analyser

    def run(self):
        self.analyser.start()
        os.kill(os.getppid(), signal.SIGUSR1)
