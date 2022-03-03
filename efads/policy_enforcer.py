import ctypes as ct
import time

from .utility import _keys_map, Checkpoint


class SimulatedPolicyEnforcer:
    def enforce(self, black_map, predictions, packets_dict, checkpoints):
        i = -1
        for sess_id, v in packets_dict.items():
            if not v.is_tracked:
                continue
            i += 1
            if predictions[i] <= 0.5:
                continue
            v.is_predicted_malicious = True
            if sess_id not in black_map:
                black_map[sess_id] = 0
                v.is_enforced = True
        checkpoints.append(Checkpoint("enforce", time.time_ns()))


class PolicyEnforcer(SimulatedPolicyEnforcer):
    def enforce(self, programs, predictions, packets_dict, checkpoints):
        black_map_ref = programs['ingress']['BLACKLISTED_IPS']
        i = -1
        for sess_id, v in packets_dict.items():
            if not v.is_tracked:
                continue
            i += 1
            if predictions[i] <= 0.5:
                continue
            v.is_predicted_malicious = True
            key = black_map_ref.Key()
            [setattr(key, name, val)
             for name, val in zip(_keys_map.keys(), sess_id)]
            if key not in black_map_ref:
                black_map_ref[key] = ct.c_ulong(0)
                v.is_enforced = True
        checkpoints.append(Checkpoint("enforce", time.time_ns()))
