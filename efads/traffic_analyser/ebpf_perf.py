import threading
import time

from ..utility import Checkpoint, ExtractionType, SessionValue, _keys_map
from .ebpf import EbpfAnalyser


class EbpfPerfAnalyser(EbpfAnalyser):
    def start(self):
        super().start()
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
        if self.analysis_state.extraction_type == ExtractionType.AGGREGATE:
            raise Exception("Unexpected perf buffer with aggregate analysis")
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
