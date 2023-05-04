import time
from threading import Thread
import sys
from io import StringIO


# COLOURS
ESC = "\033"
NOT_BOLD_RED = f"{ESC}[00;31m"
RED = f"{ESC}[1;31m"
GREEN = f"{ESC}[1;32m"
YELLOW = f"{ESC}[1;33m"
BLUE = f"{ESC}[1;34m"
LIGHTGRAY = f"{ESC}[1;37m"
DARKGRAY = f"{ESC}[1;90m"
LIGHT_ESCYAN = f"{ESC}[1;96m"
END = f"{ESC}[0m"
ITALIC = f"{ESC}[3m"
UNDERLINED = f"{ESC}[5m"
BOLD = f"{ESC}[22m"

# High Intensity backgrounds
BG_Black = f'{ESC}[0;100m'  # Black
BG_Red = f'{ESC}[0;101m'  # Red
BG_Green = f'{ESC}[0;102m'  # Green
BG_Yellow = f'{ESC}[0;103m'  # Yellow
BG_Blue = f'{ESC}[0;104m'  # Blue
BG_Purple = f'{ESC}[0;105m'  # Purple
BG_Cyan = f'{ESC}[0;106m'  # Cyan
BG_White = f'{ESC}[0;107m'  # White


class Progress:
    def __init__(self):
        self.running = True

    def progress_func(self, silence):
        if not silence:
            while self.running:
                for a in [" | ", " / ", " - ", " \\ "]:
                    if self.running:
                        output("Searching" + a, end="\r", flush=True)

                    time.sleep(0.1)


class CThread(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None

    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)

    def join(self, *args):
        Thread.join(self, *args)
        return self._return


class Tee(object):
    def __init__(self, *files):
        self.files = files

    def write(self, obj):
        for f in self.files:
            f.write(obj)

    def flush(self):
        for f in self.files:
            f.flush()


output_file = StringIO()
stdout = Tee(sys.stdout, output_file)
sys.stdout = stdout


def output(value="", file=False, end="\n", flush=False):
    global output_file
    global stdout
    if file:
        sys.stdout = stdout
        print(value, file=output_file)
    else:
        sys.stdout = sys.__stdout__
        print(value, end=end, flush=flush)
