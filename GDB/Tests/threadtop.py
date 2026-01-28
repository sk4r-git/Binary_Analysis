import gdb
import shutil

# Couleurs ANSI 256 couleurs (change la palette si tu veux)
PALETTE = [
    "\x1b[38;5;45m",   # cyan
    "\x1b[38;5;208m",  # orange
    "\x1b[38;5;82m",   # vert
    "\x1b[38;5;33m",   # bleu
    "\x1b[38;5;201m",  # magenta
    "\x1b[38;5;190m",  # jaune pâle
    "\x1b[38;5;215m",  # saumon
    "\x1b[38;5;159m",  # bleu clair
]

CUR_BG   = "\x1b[48;5;240m"
RESET    = "\x1b[0m"
DIM      = "\x1b[2m"

_thread_colors = {}
_color_idx = 0
_last_thread_id = None
_enabled = True


def _term_width():
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return 80


def _color_for(thnum):
    global _color_idx
    if thnum not in _thread_colors:
        _thread_colors[thnum] = PALETTE[_color_idx % len(PALETTE)]
        _color_idx += 1
    return _thread_colors[thnum]


def _status_char(th):
    # GDB ne fournit pas un état très riche, on fait simple
    try:
        return "S" if th.is_stopped() else "R"
    except Exception:
        return "?"


def _short_name(th):
    # name = pthread name si dispo, sinon rien
    name = getattr(th, "name", "") or ""
    return name


def _render_threads():
    if not _enabled:
        return

    try:
        inf = gdb.selected_inferior()
        threads = inf.threads()
        cur = gdb.selected_thread()
    except gdb.error:
        return

    if not threads:
        return

    width = _term_width()
    header = " Thread Monitor "
    sep_top = "═" * width
    sep_mid = "─" * width

    lines = [sep_top, header.center(width), sep_mid]

    # Entête colonnes
    lines.append(
        f"{DIM} id  lwp   S  PC/loc             name{RESET}"
    )

    for th in threads:
        pid, lwpid, tid = th.ptid
        is_cur = (th == cur)
        status = _status_char(th)
        color = _color_for(th.num)
        mark = ">" if is_cur else " "

        # PC / location courte
        try:
            frame = th.frame()
            loc = frame.name() or "??"
        except gdb.error:
            loc = "??"

        name = _short_name(th)

        s = f"{mark}{th.num:3d} {lwpid:5d} {status} {loc:<16.16} {name}"
        s = s[:width]  # éviter de dépasser la largeur

        if is_cur:
            s = f"{CUR_BG}{color}{s}{RESET}"
        else:
            s = f"{color}{s}{RESET}"

        lines.append(s)

    lines.append(sep_top)

    # On écrit sur STDERR pour ne pas mélanger avec les outputs normaux
    gdb.write("\n".join(lines) + "\n", gdb.STDERR)


def _on_stop(event):
    global _last_thread_id

    if not _enabled:
        return

    try:
        th = gdb.selected_thread()
    except gdb.error:
        return

    cur_id = th.num
    changed = (_last_thread_id is not None and cur_id != _last_thread_id)
    _last_thread_id = cur_id

    _render_threads()

    if changed:
        gdb.write(
            f"[thread switch] maintenant dans le thread #{th.num} ptid={th.ptid}\n",
            gdb.STDERR,
        )


class ThreadTopCmd(gdb.Command):
    """threadtop on|off : active/désactive le mini-dashboard threads."""

    def __init__(self):
        super().__init__("threadtop", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        global _enabled
        arg = arg.strip()
        if not arg:
            gdb.write(f"threadtop is currently {'on' if _enabled else 'off'}\n")
            return
        if arg.lower() in ("on", "1", "true"):
            _enabled = True
            gdb.write("threadtop: ON\n")
        elif arg.lower() in ("off", "0", "false"):
            _enabled = False
            gdb.write("threadtop: OFF\n")
        else:
            gdb.write("Usage: threadtop on|off\n")


# Install
ThreadTopCmd()
gdb.events.stop.connect(_on_stop)
gdb.write("[threadtop] installé (commande 'threadtop on/off')\n", gdb.STDERR)