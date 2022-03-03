from enum import Enum
import ctypes as ct
import os
import json
import time
import dataclasses

from subprocess import Popen
from .utility import GlobalResultManager, TimeWindowResultManager, Checkpoint, Costs, ExtractionType


class Action(Enum):
    STEADY = 0
    STRONG_INCREASE = 1
    STRONG_DECREASE = 2
    WEAK_INCREASE = 3
    WEAK_DECREASE = 4
    STOP = 5


class SimulatedAdjuster:
    def __init__(self, dump_dir, attackers) -> None:
        self.results = GlobalResultManager()
        self.dump_file = os.path.join(dump_dir, "results.json")
        self.global_black_map = {}
        self.real_malicious_len = len(attackers[0])
        self.attackers = dict.fromkeys([tuple(x) for x in attackers], None)
        if os.path.isfile(self.dump_file):
            os.remove(self.dump_file)

    def __del__(self):
        try:
            with open(self.dump_file, "w") as fp:
                json.dump(dataclasses.asdict(self.results), fp, indent=2)
            del self.results
        except Exception:
            pass

    def on_update(self, keys_cost, keys_size, features_cost, features_size, extraction_type):
        self.get_entry_cpu = lambda x: (Costs.KEY_INSERTION_COST.value + Costs.BLACKLIST_LOOKUP_COST.value +
                                       Costs.SPACE_LOOKUP_COST.value + keys_cost) * x.tot_pkts +\
            (Costs.STORE_PACKET_COST.value + features_cost)*len(x.pkts_or_counters) if extraction_type == ExtractionType.PERPACKET else 0
        self.get_entry_mem = lambda x: keys_size + ct.sizeof(ct.c_uint64) + ct.sizeof(ct.c_uint8) + features_size*(len(x.pkts_or_counters) if extraction_type == ExtractionType.PERPACKET else 1)    
        self.get_entry_analysed = lambda x: len(x.pkts_or_counters) if extraction_type == ExtractionType.PERPACKET else x.tot_pkts
        self.get_blacklist_cpu = lambda x: (Costs.BLACKLIST_LOOKUP_COST.value + keys_cost)*x
        self.get_blacklist_mem = lambda x: (keys_size + ct.sizeof(ct.c_uint64)) if not x else 0
        self.get_ignored_cpu = lambda x: (Costs.BLACKLIST_LOOKUP_COST.value + Costs.SPACE_LOOKUP_COST.value + keys_cost) * x

    def adjust(self, session_map, pkts_received, black_map, checkpoints):
        tw_res = TimeWindowResultManager()
        for sess_id, val in session_map.items():
            ttype = None
            is_malicious = sess_id[:self.real_malicious_len] in self.attackers
            is_predicted_malicious = val.is_predicted_malicious
            pkts_received -= val.tot_pkts
            if not val.is_tracked:
                ttype = 'tp' if is_malicious else 'tn'
                setattr(tw_res.metrics, "other_{}_pkts_no_space".format(ttype), getattr(
                    tw_res.metrics, "other_{}_pkts_no_space".format(ttype))+val.tot_pkts)
                continue
            if is_malicious and is_predicted_malicious:
                ttype = 'tp'
            elif is_predicted_malicious and is_malicious != is_predicted_malicious:
                ttype = 'fp'
            elif not is_predicted_malicious and not is_malicious:
                ttype = 'tn'
            elif not is_predicted_malicious and is_malicious != is_predicted_malicious:
                ttype = 'fn'
            else:
                raise Exception("Unable to infer the metric")

            # (check_black+check_space)*tutti_pkts + key_insert + costi features
            analysed_pkts = self.get_entry_analysed(val)
            tw_res.consumptions.os_cpu += self.get_entry_cpu(val)
            tw_res.consumptions.os_mem += self.get_entry_mem(val)
            setattr(tw_res.metrics, ttype, getattr(tw_res.metrics, ttype)+1)
            setattr(tw_res.metrics, "{}_pkts".format(ttype), getattr(
                tw_res.metrics, "{}_pkts".format(ttype))+analysed_pkts)
            setattr(tw_res.metrics, "{}_no_space_pkts".format(ttype), getattr(
                tw_res.metrics, "{}_no_space_pkts".format(ttype))+(val.tot_pkts - analysed_pkts))
            if session_map[sess_id].is_enforced:  # it must be either tp or fp
                setattr(tw_res.metrics, "{}_mit".format(ttype), getattr(
                    tw_res.metrics, "{}_mit".format(ttype)) + 1)

        checkpoints.append(Checkpoint("extracted_sessions", time.time_ns()))
        for k, v in black_map.items():
            target = 'tp' if k[:self.real_malicious_len] in self.attackers else 'fp'
            is_already_blacklisted = k in self.global_black_map
            diff_mit_pkts = v - \
                self.global_black_map[k] if is_already_blacklisted else v
            setattr(tw_res.metrics, "{}_mit_pkts".format(target), getattr(
                tw_res.metrics, "{}_mit_pkts".format(target)) + diff_mit_pkts)
            tw_res.consumptions.os_cpu += self.get_blacklist_cpu(diff_mit_pkts)
            tw_res.consumptions.os_mem += self.get_blacklist_mem(is_already_blacklisted)
            pkts_received -= diff_mit_pkts
        self.global_black_map = black_map
        checkpoints.append(Checkpoint("blackmap_sessions", time.time_ns()))

        tw_res.metrics.other_pkts_no_space = pkts_received
        tw_res.consumptions.os_cpu += self.get_ignored_cpu(pkts_received)
        
        for i, checkp in enumerate(checkpoints):
            if i == 0:
                continue
            tw_res.times[checkp.name] = checkp.value - checkpoints[i-1].value

        for k, v in tw_res.__dict__.items():
            kobj = getattr(tw_res, k)
            if isinstance(kobj, dict):
                for k in kobj.keys():
                    self.results.times[k] = kobj[k] if k not in self.results.times else self.results.times[k]+kobj[k]
            else:
                mobj = getattr(self.results, k)
                for kk, vv in kobj.__dict__.items():
                    setattr(mobj, kk, vv + getattr(mobj, kk))

        tw_res.times['update_stats'] = time.time_ns() - checkpoints[-1].value
        self.results.times['update_stats'] = tw_res.times['update_stats'] if 'update_stats' not in self.results.times\
            else self.results.times['update_stats'] + tw_res.times['update_stats']
        self.results.time_window_values.append(tw_res)
        return Action.STEADY


class AnalysisAdjuster(SimulatedAdjuster):
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
