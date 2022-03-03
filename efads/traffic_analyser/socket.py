import threading

from pypacker import psocket
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp
from pypacker.layer12 import ethernet

from ..utility import ExtractionType, SessionValue, _keys_map, get_ordered_key
from . import BaseLiveAnalyser


class SocketAnalyser(BaseLiveAnalyser):
    def __init__(self, efads):
        super().__init__(efads)
        self.interface = efads.interface
        self.timeout = efads.run_conf.debug.timeout

    def _spawn_thread(self):
        t = threading.Timer(
            self.analysis_state.time_window, self._terminate_timewindow)
        t.daemon = True
        t.start()

    def start(self):
        self.on_update()

        # If the interface is in promiscuous then here all packets are seen
        psock = psocket.SocketHndl(
            iface_name=self.interface, timeout=self.timeout)
        self._spawn_thread()
        for raw_bytes in psock:
            eth = ethernet.Ethernet(raw_bytes)
            if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None
                                      and eth[ip.IP, udp.UDP] is None
                                      and eth[ip.IP, icmp.ICMP] is None):
                continue

            sess_id = get_ordered_key([y[0](eth) for y in _keys_map.values()])

            if sess_id not in self.session_map:
                if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                    continue
                self.session_map[sess_id] = SessionValue()
            self.session_map[sess_id].tot_pkts += 1

            if self.analysis_state.extraction_type == ExtractionType.PERPACKET:
                if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                    continue
                self.session_map[sess_id].pkts_or_counters.append(
                    [y[0](eth) for y in self.analysis_state.features.values()])
            else:
                new_vals = [y[0](eth)
                            for y in self.analysis_state.features.values()]
                if not self.session_map[sess_id].pkts_or_counters:
                    self.session_map[sess_id].pkts_or_counters = new_vals
                else:
                    for i in range(len(new_vals)):
                        self.session_map[sess_id].pkts_or_counters[i] += new_vals[i]
        psock.close()

    def _terminate_timewindow(self):
        super()._terminate_timewindow()
        self._spawn_thread()
