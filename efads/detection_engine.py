import os
import random
import time
from base64 import b64decode

import numpy as np
import tensorflow as tf

from .utility import Checkpoint, ExtractionType, cint_type_limit

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

    def on_update(self, features, extraction_type, time_window, model_name, packets_per_session, batch_size):
        self.features = features
        self.time_window = time_window
        self.packets_per_session = packets_per_session
        self.batch_size = batch_size
        self.extraction_type = extraction_type

        # feature list with min and max values (None has to be set at runtime)
        feature_list = [cint_type_limit(
            x[1]) for x in self.features.values()]
        # adjust time_window max value in features
        # TODO: Fix
        if "timestamp" in self.features:
            feature_list[0] = (feature_list[0][0],
                               self.time_window)

        self.maxs = np.array([x[1] for x in feature_list])
        self.rng = np.array([x[1] - x[0] for x in feature_list])

        self.model = model_name
        if not os.path.isfile(self.model):
            content = self.model
            self.model = "/tmp/model"
            with open(self.model, "wb+") as fp:
                fp.write(b64decode(content))

        # load now the model, when sure to be in a different process
        self.model = tf.keras.models.load_model(self.model)
        tf.keras.backend.clear_session()

    def _normalize_and_padding_sample(self, sample, high: float = 1.0, low: float = 0.0):
        # if the sample is bigger than expected, we cut the sample
        if sample.shape[0] > self.packets_per_session:
            sample = sample[:self.packets_per_session, ...]
        # TODO: fix
        if "timestamp" in self.features:
            sample[:, 0] = (sample[:, 0] - sample[0][0]) / 1000000000
        # scale to linear bicolumn
        norm_sample = high - (((high - low) * (self.maxs - sample)) / self.rng)
        if self.extraction_type == ExtractionType.PERPACKET:
            # padding
            return np.pad(norm_sample, ((
                0, self.packets_per_session - sample.shape[0]), (0, 0)), 'constant', constant_values=(0, 0))
        return norm_sample

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
                np.array(v.pkts_or_counters, dtype=float)))

        data = np.array(data)
        data = np.expand_dims(data, axis=3)
        checkpoints.append(Checkpoint("manipulation", time.time_ns()))
        predictions = np.squeeze(self.model.predict(
            data, batch_size=self.batch_size), axis=1)
        checkpoints.append(Checkpoint("prediction", time.time_ns()))

        return predictions
