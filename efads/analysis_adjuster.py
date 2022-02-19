import json
import dataclasses

from .utility import GlobalResultManager


class AnalysisAdjuster:
    def __init__(self, attackers, dump_file) -> None:
        self.results = GlobalResultManager(attackers=attackers)
        self.dump_file = dump_file
    
    def handle(self, p, predictions, sess_map_or_packets, pkts_received=0, black_map={}, checkpoints=[]):        
        self.results.end_tw(predictions, sess_map_or_packets,
                            pkts_received, black_map, checkpoints)
    
    def __del__(self):
        if not hasattr(self, "results"):
            return
        with open(self.dump_file, "w") as fp:
            json.dump(dataclasses.asdict(self.results), fp, indent=2)
        del self.results