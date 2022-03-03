import json
import os
import time
from subprocess import Popen

from efads_simulator.analysis_adjuster import Action, AnalysisAdjuster


class LiveAnalysisAdjuster(AnalysisAdjuster):
    def __init__(self, dump_dir, attackers, max_duration, pid_to_monitor, top_frequence) -> None:
        super().__init__(dump_dir, attackers)
        self.stop_time = time.time_ns() + max_duration*10**9 if max_duration else None
        self.dump_top = os.path.join(dump_dir, "consumption.json")
        if os.path.isfile(self.dump_top):
            os.remove(self.dump_top)
        self.fp = open(self.dump_top, "w")
        self.proc = Popen("top -1 -p {} -b -d {}".format(pid_to_monitor,
                                                         top_frequence), shell=True, stdout=self.fp)

    def __del__(self):
        os.kill(self.proc.pid)
        os.close(self.fp)

        total_cpu = os.cpu_count()*100
        one, two = [], []
        with open(self.dump_top, "r") as fp:
            tmp = fp.read()
            if tmp:
                for k in tmp.replace("\x00", '').strip().split('\n\n'):
                    cpu_idle = 0
                    to_print = False
                    for l in k.splitlines():
                        if "python3" in l:
                            to_print = False
                            one.append(
                                float(l.split()[8].replace(",", "."))/os.cpu_count())
                        elif "%Cpu" in l:
                            to_print = True
                            cpu_idle += float(l.split("id,")
                                              [0].split("ni,")[1].replace(",", "."))
                    if to_print:
                        two.append((total_cpu-cpu_idle)*100/total_cpu)
        with open(self.dump_top, "w") as fp:
            json.dump({"efads_cpu": one, "os_cpu": two}, fp, indent=2)
        super().__del__()

    def adjust(self, session_map, pkts_received, black_map, checkpoints):
        ret = super().adjust(session_map, pkts_received, black_map, checkpoints)
        if self.stop_time is not None and time.time_ns() >= self.stop_time:
            return Action.STOP
        return ret
