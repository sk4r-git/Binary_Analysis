#!/usr/bin/env python3
import time
import random
import os, sys

RESET = "\x1b[0m"
COLORS = ["\x1b[38;5;45m", "\x1b[38;5;208m", "\x1b[38;5;82m"]

def draw(lines):
    sys.stdout.write("\x1b[H\x1b[2J")  # curseur en haut + clear écran
    for i, txt in enumerate(lines):
        color = COLORS[i % len(COLORS)]
        sys.stdout.write(color + txt + RESET + "\n")
    sys.stdout.flush()

items = ["thread A", "thread B", "thread C", "thread D"]

# terminal en mode "plein écran" pour pas polluer l'historique
# os.system("tput smcup")
try:
    while True:
        random.shuffle(items)
        draw([f"{i}: {name}" for i, name in enumerate(items)])
        time.sleep(0.3)
finally:
    os.system("tput rmcup")  # revient à l'écran normal