import os
import random
import time
from base64 import b64decode

import numpy as np
import tensorflow as tf
from dechainy.utility import cint_type_limit

from .utility import Checkpoint

os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

SEED = 1
# Seed Random Numbers
os.environ['PYTHONHASHSEED'] = str(SEED)
np.random.seed(SEED)
random.seed(SEED)
tf.random.set_seed(SEED)
tf.keras.backend.set_image_data_format('channels_last')


class DetectionEngine:
    def __del__(self):
        try:
            del self.model
            tf.keras.backend.clear_session()
        except Exception:
            pass

    def on_update(self, analysis_state):
        self.analysis_state = analysis_state

        # feature list with min and max values (None has to be set at runtime)
        feature_list = [cint_type_limit(
            x[1]) for x in self.analysis_state.features.values()]
        # adjust time_window max value in features
        if "timestamp" in self.analysis_state.features:
            feature_list[0] = (feature_list[0][0],
                               self.analysis_state.time_window)

        self.maxs = np.array([x[1] for x in feature_list])
        self.rng = np.array([x[1] - x[0] for x in feature_list])

        self.model = self.analysis_state.model_name
        if not os.path.isfile(self.model):
            content = self.model
            self.model = "/tmp/model"
            with open(self.model, "wb+") as fp:
                fp.write(b64decode(content))

        tf.keras.backend.clear_session()
        # load now the model, when sure to be in a different process
        self.model = tf.keras.models.load_model(self.model)

        # warmup
        for _ in range(10):
            self.model.predict(np.expand_dims(np.array([
                self._normalize_and_padding_sample(np.array([[random.randint(
                    0, 10) for _ in range(analysis_state.active_features)]], dtype=float)),
            ]), axis=3), batch_size=analysis_state.batch_size)

    def _normalize_and_padding_sample(self, sample, high: float = 1.0, low: float = 0.0):
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > self.analysis_state.packets_per_session:
            sample = sample[:self.analysis_state.packets_per_session, ...]
        if "timestamp" in self.analysis_state.features:
            sample[:, 0] = (sample[:, 0] - sample[0][0]) / 1000000000
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (self.maxs - sample)) / self.rng)
        # padding
        return np.pad(norm_sample, ((
            0, self.analysis_state.packets_per_session - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))

    def predict(self, packets_dict, checkpoints):
        if not packets_dict:
            ttmp = time.time_ns()
            checkpoints.append(Checkpoint("manipulation", ttmp))
            checkpoints.append(Checkpoint("prediction", ttmp))
            return []

        data = []
        
        for v in packets_dict.values():
            if not v.is_tracked:
                continue
            data.append(self._normalize_and_padding_sample(
                np.array(v.pkts, dtype=float)))
            
        data = np.array(data)
        data = np.expand_dims(data, axis=3)
        checkpoints.append(Checkpoint("manipulation", time.time_ns()))
        predictions = np.squeeze(self.model.predict(
            data, batch_size=self.analysis_state.batch_size), axis=1)
        checkpoints.append(Checkpoint("prediction", time.time_ns()))

        return predictions
