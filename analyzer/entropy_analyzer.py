import math
from collections import Counter


def calculate_entropy(file_path):
    try:
        with open(file_path, "rb") as file:
            data = file.read()

        if not data:
            return 0.0

        frequency = Counter(data)
        data_length = len(data)

        entropy = 0.0

        for count in frequency.values():
            probability = count / data_length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    except OSError:
        return 0.0
