import ctypes as ct
import threading
import time
from abc import abstractclassmethod
from multiprocessing import Process
from multiprocessing.pool import ThreadPool
from typing import Dict

from pypacker import ppcap, psocket
from pypacker.layer3 import icmp, ip
from pypacker.layer4 import tcp, udp
from pypacker.layer12 import ethernet

from .utility import AnalysisState, RunState, SessionValue, _keys_map


class BaseAnalyser(Process):
    def __init__(self, shared_conf, shared_queue, run_state):
        Process.__init__(self)
        self.daemon = True
        self.shared_queue = shared_queue
        self.shared_conf = shared_conf
        self.run_state: RunState = run_state

    def on_update(self):
        self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})
        self.p = self.analysis_state.reconstruct_programs(
            self.run_state.main_pid, self.run_state.mode)
        self.blacklist_map = self.p['ingress']["BLACKLISTED_IPS"]
        self.features_size = self.analysis_state.features_size

    @abstractclassmethod
    def run(self):
        pass

    def queue_send(self, sessions_map_or_packets, new_pkts, black_map, checkpoints):
        self.shared_queue.put((sessions_map_or_packets, new_pkts, black_map, checkpoints))


class SimulatedAnalyser(BaseAnalyser):
    def run(self):
        self.on_update()
        self.session_map: Dict[str, SessionValue] = {}
        cnt = 0
        target_pkt_map = self.p['ingress'].bpf["PACKET_COUNTER"]
        for pcap_file in self.run_state.debug.pcaps:
            start_time_window = -1
            for i, (ts, buf) in enumerate(ppcap.Reader(filename=pcap_file)):
                if i == 0:
                    start_time_window = ts

                # start_time_window is used to group packets/flows captured in a time-window
                if ts > start_time_window + (self.analysis_state.time_window * 10**9):
                    start_time_window = ts
                    self.terminate_timewindow()
                    cnt += 1
                    if cnt % 2 == 0:
                        target_pkt_map = self.p['ingress'].bpf["PACKET_COUNTER"]
                        val = self.shared_queue.get()
                        while val is not True:
                            self.shared_queue.put(val)
                            time.sleep(1)
                            val = self.shared_queue.get()
                    else:
                        target_pkt_map = self.p['ingress'].bpf_1["PACKET_COUNTER_1"]

                eth = ethernet.Ethernet(buf)
                if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None and eth[ip.IP, udp.UDP] is None and eth[ip.IP, icmp.ICMP] is None):
                    continue

                target_pkt_map[0] = ct.c_ulong(target_pkt_map[0].value + 1)
                sess_id = [y[0](eth) for y in _keys_map.values()]
                # lowest IP goes first in the identifier, to facilitate grouping packets
                if sess_id[1] < sess_id[0]:
                    sess_id = [sess_id[1], sess_id[0],
                               sess_id[3], sess_id[2], sess_id[4]]

                key = self.blacklist_map.Key()
                [setattr(key, n, sess_id[j]) for j, n in enumerate(
                    _keys_map.keys())]

                if key in self.blacklist_map:
                    self.blacklist_map[key] = ct.c_ulong(
                        self.blacklist_map[key].value + 1)
                    continue

                sess_id = tuple(sess_id)
                if sess_id not in self.session_map:
                    if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                        continue
                    self.session_map[sess_id] = SessionValue()
                self.session_map[sess_id].tot_pkts += 1

                if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                    continue
                self.session_map[sess_id].pkts.append(
                    [y[0](eth) for y in self.analysis_state.features.values()])
            if self.session_map:
                self.terminate_timewindow()
            print(f"Finito {pcap_file}")

        # terminate by sending no data (checkpoints)
        self.queue_send({}, 0, {}, [])

    def terminate_timewindow(self):
        checkpoint_0 = time.time_ns()

        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()
        checkpoint_1 = time.time_ns()
        black_map = {tuple([getattr(k, n) for n in _keys_map.keys()]) : v for k, v in self.blacklist_map.items_lookup_batch()}
        new_pkts = self.p['ingress']["PACKET_COUNTER"][0].value
        self.p['ingress']["PACKET_COUNTER"].clear()
        tmp = self.session_map.copy()
        self.session_map.clear()
        checkpoint_2 = time.time_ns()
        self.queue_send(
            tmp, new_pkts, black_map, [checkpoint_0, checkpoint_1, checkpoint_2])


class SocketAnalyser(BaseAnalyser):
    def run(self):
        self.on_update()
        self.session_map = {}

        t = threading.Timer(
            self.analysis_state.time_window, self.terminate_timewindow)
        t.daemon = True
        t.start()

        # If the interface is in promiscuous then here all packets are seen
        psock = psocket.SocketHndl(
            iface_name=self.run_state.interface, timeout=self.run_state.timeout)
        for raw_bytes in psock:
            eth = ethernet.Ethernet(raw_bytes)
            if eth[ip.IP] is None or (eth[ip.IP, tcp.TCP] is None and eth[ip.IP, udp.UDP] is None and eth[ip.IP, icmp.ICMP] is None):
                continue

            sess_id = [y[0](eth) for y in _keys_map.values()]

            # lowest IP goes first in the identifier, to facilitate grouping packets
            if sess_id[1] < sess_id[0]:
                sess_id = [sess_id[1], sess_id[0],
                           sess_id[3], sess_id[2], sess_id[4]]

            sess_id = tuple(sess_id)

            if sess_id not in self.session_map:
                if len(self.session_map) == self.analysis_state.sessions_per_time_window:
                    continue
                self.session_map[sess_id] = SessionValue()
            self.session_map[sess_id].tot_pkts += 1

            if self.session_map[sess_id].tot_pkts > self.analysis_state.packets_per_session:
                continue

            self.session_map[sess_id].pkts.append(
                [y[0](eth) for y in self.analysis_state.features.values()])
        psock.close()

    def terminate_timewindow(self):
        checkpoint_0 = time.time_ns()

        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()

        checkpoint_1 = time.time_ns()
        new_pkts = self.p['ingress']["PACKET_COUNTER"][0].value
        self.p['ingress']["PACKET_COUNTER"].clear()
        tmp = self.session_map.copy()
        self.session_map.clear()
        checkpoint_2 = time.time_ns()
        t = threading.Timer(self.analysis_state.time_window,
                            self.terminate_timewindow)
        t.daemon = True
        t.start()
        self.queue_send(
            tmp, new_pkts, [checkpoint_0, checkpoint_1, checkpoint_2])


class EbpfPerfAnalyser(BaseAnalyser):
    def run(self):
        self.on_update()
        self.packets = []
        self.p['ingress']['CUSTOM_TO_CP'].open_perf_buffer(self.handle_packet)
        t = threading.Timer(
            self.analysis_state.time_window, self.terminate_timewindow)
        t.daemon = True
        t.start()
        while True:
            self.p['ingress'].bpf.perf_buffer_poll()

    def terminate_timewindow(self):
        checkpoint_0 = time.time_ns()

        for hook in ['ingress', 'egress']:
            if not self.p[hook]:
                continue
            self.p[hook].trigger_read()

        checkpoint_1 = time.time_ns()
        pkts = self.p['ingress']["PACKET_COUNTER"][0].value
        self.p['ingress']["PACKET_COUNTER"].clear()
        tmp = self.packets.copy()
        self.packets.clear()
        sess = self.extract_sessions(
            self.p["ingress"]["SESSIONS_TRACKED_DDOS"])  # TODO: USE IT

        checkpoint_2 = time.time_ns()
        t = threading.Timer(
            self.analysis_state.time_window, self.terminate_timewindow)
        t.daemon = True
        t.start()
        self.queue_send(tmp, pkts[checkpoint_0, checkpoint_1, checkpoint_2])

    def handle_packet(self, cpu, data, size):
        self.packets.append((ct.c_char * size).from_address(data).raw)

    def extract_sessions(self, table):
        return len([1 for _, _ in table.items_lookup_and_delete_batch()])


class EbpfFullAnalyser(BaseAnalyser):

    def run_full_ebpf(self):
        # pool with 1 thread used to perform async session map erasion
        pool = ThreadPool()

        while True:
            time.sleep(self.analysis_state.time_window)
            # TODO CHECK if __debug__
            checkpoint_0 = time.time_ns()

            for hook in ['ingress', 'egress']:
                if not self.p[hook]:
                    continue
                self.p[hook].trigger_read()

            task = pool.apply_async(self.extract_sessions, args=(
                self.p['ingress']["SESSIONS_TRACKED_DDOS"],))

            checkpoint_1 = time.time_ns()
            new_pkts = self.p['ingress']["PACKET_COUNTER"][0].value
            self.p['ingress']["PACKET_COUNTER"].clear()

            packets = [(ct.c_char * ct.sizeof(self.analysis_state.features_size)).from_buffer(
                x).raw for x in self.p['ingress']["PACKET_BUFFER_DDOS"].values()]
            sess = task.get()  # TODO: USE IT
            checkpoint_2 = time.time_ns()

            threading.Thread(target=self.queue_send, args=(
                packets, new_pkts, [checkpoint_0, checkpoint_1, checkpoint_2],), daemon=True).start()

    def extract_sessions(self, table):
        return len([1 for _, _ in table.items_lookup_and_delete_batch()])
