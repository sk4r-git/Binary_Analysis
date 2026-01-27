import gdb
import subprocess

gdb.execute("set follow-fork-mode parent")
gdb.execute("set detach-on-fork off")
def on_new_inferior(event):
    inf = event.inferior
    pid = inf.pid

    # On garde l'inferior 1 dans ce gdb, on détache les suivants.
    if inf.num == 1 or pid <= 0:
        return

    gdb.write(f"[auto-fork] Detach inferior {inf.num} (pid {pid}) "
              f"et ouverture d'un nouveau gdb...\n")

    # Détache uniquement cet inferior
    gdb.execute(f"detach inferior {inf.num}", from_tty=False)

    # Ouvre un nouveau terminal avec un gdb attaché au process enfant
    subprocess.Popen(["xterm", "-e", "gdb", "-p", str(pid)])

# Raccroche le handler
gdb.events.new_inferior.connect(on_new_inferior)