import gdb

gdb.execute("set follow-fork-mode child")
gdb.execute("set detach-on-fork off")