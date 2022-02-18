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
import time, setproctitle
from typing import OrderedDict
from dechainy.configurations import ProbeConfig

from bcc.table import PerCpuArray
from dechainy.plugins import Plugin
from dechainy.utility import ipv4_to_string, port_to_host_int, protocol_to_string
from multiprocessing import Condition, Process

# cond to start extracting, every time_window
shared_cond = Condition()

# dictionary of features and their min/max values
feature_list = OrderedDict([
    ("n_packets", [0, None]),
    ("n_packets_reverse", [0, None]),
    ("n_bytes", [0, None]),
    ("n_bytes_reverse", [0, None]),
    ("start_timestamp", [0, None])
    ("alive_timestamp", [0, None])
])


# TODO: implement dynamic features in Control Plane
class Extractor(Process):

    def __init__(self, probe: Plugin):
        global feature_list
        Process.__init__(self, daemon=True)
        self.probe = probe

    @staticmethod
    def divide(i: float, j: float) -> float:
        return i / j if j else -1

    def run(self):
        global shared_cond, shared_queue, session_key, feature_list
        setproctitle.setproctitle('DeChainy-Extractor')

        exec_number = 0

        while True:
            exec_number += 1
            with shared_cond:
                shared_cond.wait()
                
                checkpoint_0 = time.time_ns()

                self.probe["egress"].trigger_read()
                self.probe["ingress"].trigger_read()

                checkpoint_1 = time.time_ns()
                
                ret = self.__extract_data(self.probe["ingress"]["SESSIONS_TRACKED_CRYPTO"])
                
                checkpoint_2 = time.time_ns()

                shared_cond.notify_all()
            # Decide what to do with this data
            print({
                "exec_number": exec_number,
                "controls_time": checkpoint_1 - checkpoint_0,
                "ebpf_time": checkpoint_2 - checkpoint_1,
                "flows": ret
            })

    @staticmethod
    def __extract_data(table: PerCpuArray):
        ret = []
        for key, values in table.items():
            correct_key, features = Extractor.sum_cpu_values(values, key)
            seconds = features[6] / 1000000000      # duration (s)
            ret.append({"id": correct_key, "value": [
                features[5],                        # last timestamp
                features[4],                        # server method
                features[0],                        # client packets
                features[1],                        # server packets
                features[2],                        # client bits
                features[3],                        # server bits
                features[6],                        # duration (ns)
                (                       # client pkts per sec
                    features[0],
                    seconds),
                Extractor.divide(                       # server pkts per sec
                    features[1],
                    seconds),
                Extractor.divide(                       # client bits per sec
                    features[2],
                    seconds),
                Extractor.divide(                       # server bits per sec
                    features[3],
                    seconds),
                Extractor.divide(                       # client bits over pkts
                    features[2],
                    features[0]),
                Extractor.divide(                       # server bits over pkts
                    features[3],
                    features[1]),
                Extractor.divide(                       # server pkts over client pkts
                    features[1],
                    features[0]),
                Extractor.divide(                       # server bits over client bits
                    features[3],
                    features[2])]})
            del table[key]
        return ret

    @staticmethod
    def sum_cpu_values(values, key):
        features = [0] * 8
        # summing each cpu values
        for value in values:
            features[0] += value.n_packets
            features[1] += value.n_packets_reverse
            features[2] += value.n_bytes * 8
            features[3] += value.n_bytes_reverse * 8
            if value.method != 0:
                features[4] = value.method
            if value.alive_timestamp > features[5]:
                features[5] = value.alive_timestamp
            if value.start_timestamp > features[6]:
                features[6] = value.start_timestamp
            if value.server_ip != 0:
                features[7] = value.server_ip
        # modifying fields according to client-server and parsing Identifiers
        if features[7] == key.saddr:
            features[0], features[1], features[2], features[3] = features[1], features[0], features[3], features[2]
            correct_key = (key.daddr, key.dport, key.saddr, key.sport, key.proto)
        else:
            correct_key = (key.saddr, key.sport, key.daddr, key.dport, key.proto)

        features = features[:6] + [features[5] - features[6]]
        correct_key = (
            ipv4_to_string(correct_key[0]),
            port_to_host_int(correct_key[1]),
            ipv4_to_string(correct_key[2]),
            port_to_host_int(correct_key[3]),
            protocol_to_string(correct_key[4])
        )
        return correct_key, features


def post_compilation(probe: Plugin):
    Extractor(probe).start()

def pre_compilation(config: ProbeConfig):
    global feature_list, MAX_FLOW_LEN, model_path, N_TIMEWINDOWS_EMPTY

    # adjust time_window max value in features
    feature_list['start_timestamp'][1] = config.time_window
    feature_list['alive_timestamp'][1] = config.time_window

    # set default features active
    if not config.cflags:
        raise Exception("The test need features to be specified")
    
    # remove unused features
    cflags = [x.split('-D')[1].split('=')[0].lower() for x in config.cflags if '-D' in x and '=' in x]
    for key in list(feature_list.keys()):
        if key not in cflags:
            feature_list.pop(key)

def reaction_function(probe: Plugin):
    global shared_cond
    with shared_cond:
        shared_cond.notify()
        shared_cond.wait()
