import ctypes as ct

from .utility import _keys_map

class PolicyEnforcer:
    def handle(self, map_ref, predictions, sess_map_or_packets):
        for i, p in zip(sess_map_or_packets, predictions):
            if p <= 0.5:
                continue
            key = map_ref.Key()
            [setattr(key, n, i[j]) for j, n in enumerate(_keys_map.keys())]
            if key not in map_ref:
                map_ref[key] = ct.c_ulong(0)
