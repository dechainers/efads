import time

from ..utility import *
from . import BaseLiveAnalyser


class EbpfAnalyser(BaseLiveAnalyser):
    def start(self):
        super().start()
        while True:
            time.sleep(self.analysis_state.time_window)
            self.checkpoints.append(Checkpoint("begin", time.time_ns()))
            self._trigger_read()
            self.checkpoints.append(Checkpoint("controls", time.time_ns()))
            self._extract_sessions(self.p['ingress']["SESSIONS_TRACKED_DDOS"])
            self.checkpoints.append(Checkpoint(
                "extract_sessions", time.time_ns()))
            self.p['ingress']["COUNTERS"].clear()
            if self.analysis_state.extraction_type == ExtractionType.PERPACKET:
                self._extract_packets(self.p['ingress']["PACKET_BUFFER_DDOS"])
                self.checkpoints.append(Checkpoint(
                    "extract_packets", time.time_ns()))
            self._terminate_timewindow(skip_trigger=True)

    def _extract_packets(self, queue):
        for p in queue.values():
            sess_id = tuple([getattr(p.id, x) for x in _keys_map.keys()])
            features = [getattr(p, x) for x in self.analysis_state.features]
            self.session_map[sess_id].pkts_or_counters.append(features)

    def _extract_sessions(self, table):
        for k, v in table.items_lookup_and_delete_batch():
            conv_key = tuple([getattr(k, x) for x in _keys_map.keys()])
            if conv_key not in self.session_map:
                self.session_map[conv_key] = SessionValue()
            self.session_map[conv_key].tot_pkts = v.pkts
            self.session_map[conv_key].is_tracked = v.is_tracked
            if self.analysis_state.extraction_type == ExtractionType.AGGREGATE:
                self.session_map[conv_key].pkts_or_counters = [
                    getattr(v.features, x) for x in self.analysis_state.features]
