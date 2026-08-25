import pickle


def vulnerable(data):
    return pickle.loads(data)


def safe(data):
    raise ValueError("use a safe structured format instead of pickle")
