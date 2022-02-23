from enum import Enum
import json
import time
import dataclasses

from .utility import GlobalResultManager, TimeWindowResultManager, Checkpoint, Costs


class Action(Enum):
    STEADY = 0
    STRONG_INCREASE = 1
    STRONG_DECREASE = 2
    WEAK_INCREASE = 3
    WEAK_DECREASE = 4


class AnalysisAdjuster:
    def __init__(self, dump_file, attackers={}) -> None:
        self.results = GlobalResultManager()
        self.dump_file = dump_file
        self.global_black_map = {}
        self.real_malicious_len = len(attackers[0])
        self.attackers = dict.fromkeys([tuple(x) for x in attackers], None)

    def __del__(self):
        try:
            with open(self.dump_file, "w") as fp:
                json.dump(dataclasses.asdict(self.results), fp, indent=2)
            del self.results
        except Exception:
            pass

    def on_update(self, keys_cost, keys_size, features_cost, features_size):
        self.keys_size = keys_size
        self.keys_cost = keys_cost
        self.features_size = features_size
        self.features_cost = features_cost

    # TODO: aggiungi os_cpu e mem per strutture in userspace (?)
    def adjust(self, session_map, pkts_received, black_map, checkpoints):
        tw_res = TimeWindowResultManager()
        for sess_id, val in session_map.items():
            ttype = None
            is_malicious = sess_id[:self.real_malicious_len] in self.attackers
            is_predicted_malicious = val.is_predicted_malicious
            pkts_received -= val.ignored_pkts + val.received_pkts

            if not val.is_tracked:
                ttype = 'tp' if is_malicious else 'tn'
                setattr(tw_res.metrics, "other_{}_pkts_no_space".format(ttype), getattr(tw_res.metrics, "other_{}_pkts_no_space".format(ttype))+1)
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
            tw_res.consumptions.os_cpu += (Costs.KEY_INSERTION_COST.value + Costs.BLACKLIST_LOOKUP_COST.value + Costs.SPACE_LOOKUP_COST.value + val.tot_pkts) * self.keys_cost + (Costs.STORE_PACKET_COST.value + self.features_cost)*val.received_pkts
            tw_res.consumptions.os_mem += self.keys_size[0] + self.keys_size[1] + self.features_size*val.received_pkts
            setattr(tw_res.metrics, ttype, getattr(tw_res.metrics, ttype)+1)
            setattr(tw_res.metrics, "{}_pkts".format(ttype), getattr(
                tw_res.metrics, "{}_pkts".format(ttype))+val.received_pkts)
            setattr(tw_res.metrics, "{}_no_space_pkts".format(ttype), getattr(
                tw_res.metrics, "{}_no_space_pkts".format(ttype))+val.ignored_pkts)
            if session_map[sess_id].is_enforced: # it must be either tp or fp
                setattr(tw_res.metrics, "{}_mit".format(ttype), getattr(tw_res.metrics, "{}_mit".format(ttype)) + 1)
            
        checkpoints.append(Checkpoint("extracted_sessions", time.time_ns()))
        for k, v in black_map.items():
            target = 'tp' if k[:self.real_malicious_len] in self.attackers else 'fp'
            diff_mit_pkts = v - self.global_black_map[k] if k in self.global_black_map else v
            setattr(tw_res.metrics, "{}_mit_pkts".format(target), getattr(tw_res.metrics, "{}_mit_pkts".format(target)) + diff_mit_pkts)
            tw_res.consumptions.os_cpu += (Costs.BLACKLIST_LOOKUP_COST.value + self.keys_cost)*diff_mit_pkts
            tw_res.consumptions.os_mem += self.keys_size[0] + self.keys_size[1]
            pkts_received -= diff_mit_pkts
        self.global_black_map = black_map
        checkpoints.append(Checkpoint("blackmap_sessions", time.time_ns()))

        tw_res.metrics.other_pkts_no_space = pkts_received
        tw_res.consumptions.os_cpu += (Costs.BLACKLIST_LOOKUP_COST.value + Costs.SPACE_LOOKUP_COST.value + self.keys_cost) * pkts_received
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
        self.results.times['update_stats'] = tw_res.times['update_stats'] if 'update_stats' not in self.results.times else self.results.times['update_stats'] + tw_res.times['update_stats']
        self.results.time_window_values.append(tw_res)        
        return Action.STEADY
