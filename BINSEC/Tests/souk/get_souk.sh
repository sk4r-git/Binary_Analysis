#!/bin/sh
wget https://github.com/Angelo942/FCSC2022/raw/main/Rev-souk-Easy/souk
chmod +x souk
gdb -x $SOUK_PATH/command --args ./souk
binsec -sse -sse-script $SOUK_PATH/crackme.ini -sse-depth 100000  -sse-qmerge 100 ./core.snapshot
