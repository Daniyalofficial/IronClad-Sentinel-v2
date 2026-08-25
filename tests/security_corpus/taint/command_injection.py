import os
import subprocess


def vulnerable(user_input):
    return os.system("ping " + user_input)


def safe(user_input):
    return subprocess.run(["ping", "-c", "1", user_input], check=True)
