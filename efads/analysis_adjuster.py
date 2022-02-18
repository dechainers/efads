from multiprocessing import Process
from .utility import RunState, AnalysisState


class AnalysisAdjuster(Process):

    def __init__(self, shared_conf, run_state):
        Process.__init__(self)
        self.daemon = True
        self.shared_conf = shared_conf
        self.run_state: RunState = run_state

    def on_update(self):
        self.analysis_state: AnalysisState = self.shared_conf.__deepcopy__({})

    def run(self):
        self.on_update()
        # TODO implement
        while True:
            pass
