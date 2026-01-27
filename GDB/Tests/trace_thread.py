import gdb

HILIGHT = "\x1b[7m"  # vidéo inversée
RESET   = "\x1b[0m"
DIM     = "\x1b[2m"

_last_thread_global_num = None

def _format_thread(th, current):
    # Sous Linux: ptid = (pid, lwpid, tid); lwpid ~= TID
    pid, lwpid, _ = th.ptid
    status = "S" if th.is_stopped() else "R"
    name = th.name or ""
    base = f"{th.num}:{lwpid}({status})"
    if name:
        base += f":{name}"
    if th == current:
        base = f"{HILIGHT}{base}{RESET}"
    else:
        base = base
    return base

def show_threads(current_thread):
    try:
        inf = current_thread.inferior
    except AttributeError:
        inf = gdb.selected_inferior()

    threads = inf.threads()
    if not threads:
        return

    line = "Threads: " + " | ".join(_format_thread(th, current_thread) for th in threads)
    # On écrit sur stderr pour ne pas polluer la sortie normale
    gdb.write(line + "\n", gdb.STDERR)

def on_stop(event):
    print("ON  STOP TRIGGERED")
    global _last_thread_global_num

    # Quel thread a provoqué le stop ?
    th = getattr(event, "thread", None)
    if th is None:
        try:
            th = gdb.selected_thread()
        except gdb.error:
            return

    cur_id = th.global_num
    changed = (_last_thread_global_num is not None and cur_id != _last_thread_global_num)
    _last_thread_global_num = cur_id

    show_threads(th)

    if changed:
        gdb.write(f"[thread switch] maintenant dans le thread #{th.num} "
                  f"(ptid={th.ptid})\n", gdb.STDERR)

# Raccroche le handler
gdb.events.stop.connect(on_stop)