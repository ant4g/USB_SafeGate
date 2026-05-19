#!/usr/bin/env python3
"""SafeGate Dashboard — dormant Tk window that pops on USB events.

Runs in the user's desktop session (started via XDG autostart). Talks to
host_gate.py daemon over /run/safegate/dashboard.sock (newline-delimited
JSON). Forces itself on top when an event arrives. For UNKNOWN verdicts,
offers "Mount anyway" / "Block" buttons.
"""

import json
import os
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk


def _log(msg):
    print(f"[dashboard] {msg}", file=sys.stderr, flush=True)

SOCKET_PATH = "/run/safegate/dashboard.sock"
RECONNECT_DELAY = 3        
AUTO_HIDE_SAFE = 6000      
AUTO_HIDE_DETACHED = 6000  


# colour bands
BG_IDLE    = "#CACACA"
BG_BUSY    = "#CACACA"
BG_SAFE    = "#1b672d"
BG_UNSAFE  = "#5f151b"
BG_UNKNOWN = "#ffc524"

FG_SAFE    = "#FFFFFF"
FG_UNSAFE  = "#ffffff"
FG_UNKNOWN = "#000000"
FG_BUSY    = "#000000"


class Dashboard:
    def __init__(self):
        self.events = queue.Queue()
        self.sock = None
        self.sock_lock = threading.Lock()
        self.current_serial = None
        self.locked = False  
        self.root = tk.Tk()
        self.root.title("SafeGate")
        self.root.geometry("560x260")
        self._center()
        self.root.withdraw()
        self.root.protocol("WM_DELETE_WINDOW", self._hide)

        self._build_ui()

        
        threading.Thread(target=self._reader_loop, daemon=True).start()

        
        self.root.after(100, self._drain_events)

    # ---------- UI ----------

    def _build_ui(self):
        self.banner = tk.Label(self.root, text="", font=("Sans", 18, "bold"),
                               bg=BG_IDLE, pady=18)
        self.banner.pack(fill="x")

        self.subtitle = tk.Label(self.root, text="", font=("Sans", 11),
                                 bg=BG_IDLE, pady=6)
        self.subtitle.pack(fill="x")

        self.detail = tk.Label(self.root, text="", font=("Mono", 10),
                               bg=BG_IDLE, pady=4, wraplength=520, justify="left")
        self.detail.pack(fill="x")

        self.button_frame = tk.Frame(self.root, bg=BG_IDLE)
        self.button_frame.pack(fill="x", side="bottom", pady=10)

        for w in (self.root, self.banner, self.subtitle, self.detail, self.button_frame):
            w.configure(bg=BG_IDLE)

    def _set_band(self, bg, fg=None):
        for w in (self.root, self.banner, self.subtitle, self.detail, self.button_frame):
            w.configure(bg=bg)
        if fg is not None:
            self.banner.configure(fg=fg)
            self.subtitle.configure(fg=fg)
            self.detail.configure(fg=fg)

    def _clear_buttons(self):
        for child in self.button_frame.winfo_children():
            child.destroy()

    def _center(self):
        self.root.update_idletasks()
        w, h = 560, 260
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 3
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    def _raise(self):
        self.root.deiconify()
        self.root.lift()
        self.root.attributes("-topmost", True)
        self.root.focus_force()
        # bell once to draw attention
        try:
            self.root.bell()
        except tk.TclError:
            pass

    def _hide(self):
        self.root.withdraw()
        self.current_serial = None
        self.locked = False

    # ---------- Socket ----------

    def _reader_loop(self):
        _log(f"reader thread starting; uid={os.getuid()} groups={os.getgroups()}")
        while True:
            try:
                _log(f"connecting to {SOCKET_PATH} ...")
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.connect(SOCKET_PATH)
                with self.sock_lock:
                    self.sock = s
                _log("connected.")
                f = s.makefile("r", encoding="utf-8")
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    _log(f"recv: {line}")
                    try:
                        ev = json.loads(line)
                    except Exception as e:
                        _log(f"bad json: {e}")
                        continue
                    self.events.put(ev)
                _log("socket EOF, reconnecting...")
            except Exception as e:
                _log(f"connect/read error: {type(e).__name__}: {e}")
            with self.sock_lock:
                self.sock = None
            time.sleep(RECONNECT_DELAY)

    def _send(self, msg):
        with self.sock_lock:
            if not self.sock:
                return False
            try:
                self.sock.sendall((json.dumps(msg) + "\n").encode())
                return True
            except OSError:
                return False

    # ---------- Event handling ----------

    def _drain_events(self):
        try:
            while True:
                ev = self.events.get_nowait()
                self._handle(ev)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    def _handle(self, ev):
        event = ev.get("event")
        serial = ev.get("serial")
        # While locked (UNSAFE awaiting acknowledgement), drop every event
        # except a fresh detection of a different device.
        if self.locked and not (event == "detected" and serial != self.current_serial):
            _log(f"locked — ignoring {event} for {serial}")
            return
        if event == "detected":
            self.current_serial = serial
            self._clear_buttons()
            self._set_band(BG_BUSY, FG_BUSY)
            self.banner.configure(text="USB detected")
            vid = ev.get("vendor", "?")
            pid = ev.get("product", "?")
            self.subtitle.configure(text=f"Vendor {vid}  Product {pid}")
            self.detail.configure(text=f"Serial: {serial}")
            self._raise()

        elif event == "vm_starting":
            self.banner.configure(text="Starting scanner VM…")
            self.subtitle.configure(text="Please wait")
            self._raise()

        elif event == "scanning":
            self.banner.configure(text="Scanning USB contents…")
            self.subtitle.configure(text="Hashing files and querying VirusTotal")
            self._raise()

        elif event == "result":
            verdict = ev.get("verdict", "?")
            if verdict == "SAFE":
                self._set_band(BG_SAFE, FG_SAFE)
                self.banner.configure(text="✓ SAFE")
                self.subtitle.configure(text="All files clean according to VirusTotal")
                self.detail.configure(text=f"Serial: {serial}")
            elif verdict == "UNSAFE":
                self._set_band(BG_UNSAFE, FG_UNSAFE)
                self.banner.configure(text="✗ UNSAFE — device blocked")
                self.subtitle.configure(text="Malicious file detected. NOT mounted.")
                self.detail.configure(
                    text=f"Serial: {serial}\nUnplug the device."
                )
                self.locked = True  # require explicit acknowledgement
                self._clear_buttons()
                ttk.Button(
                    self.button_frame,
                    text="Dismiss",
                    command=self._hide,
                ).pack(pady=6)
            elif verdict == "UNKNOWN":
                self._set_band(BG_UNKNOWN, FG_UNKNOWN)
                self.banner.configure(text="? UNKNOWN — file(s) not in VirusTotal DB")
                self.subtitle.configure(text="VirusTotal has no record for at least one file.")
                self.detail.configure(text=f"Serial: {serial}\nMount at your own risk.")
                self._clear_buttons()
                ttk.Button(self.button_frame, text="Mount anyway (at own risk)",
                           command=lambda s=serial: self._decide(s, "mount_anyway")
                           ).pack(side="left", padx=10, pady=6)
                ttk.Button(self.button_frame, text="Block",
                           command=lambda s=serial: self._decide(s, "block")
                           ).pack(side="right", padx=10, pady=6)
            self._raise()

        elif event == "mounted":
            self._set_band(BG_SAFE, FG_SAFE)
            self.banner.configure(text="✓ Mounted")
            self.subtitle.configure(text=f"Available at {ev.get('path','?')}")
            self.detail.configure(text=f"Serial: {serial}")
            self._raise()
            self.root.after(AUTO_HIDE_SAFE, self._hide)

        elif event == "detached":
            self._set_band(BG_UNSAFE, FG_UNSAFE)
            self.banner.configure(text="USB detached")
            self.subtitle.configure(text=ev.get("msg", "Device removed from system."))
            self.detail.configure(text=f"Serial: {serial}")
            self._raise()
            self.root.after(AUTO_HIDE_DETACHED, self._hide)

        elif event == "error":
            self._set_band(BG_UNSAFE, FG_UNSAFE)
            self.banner.configure(text="SafeGate error")
            self.subtitle.configure(text=ev.get("msg", "?"))
            self.detail.configure(text=f"Serial: {serial}")
            self._raise()

    def _decide(self, serial, action):
        self._send({"action": action, "serial": serial})
        self._clear_buttons()
        self.subtitle.configure(text=f"Sent decision: {action}")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    Dashboard().run()
