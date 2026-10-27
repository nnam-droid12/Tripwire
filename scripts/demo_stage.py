"""Full-screen "stage" that shows scenario screens for the live demo.

Reads image paths, one per line, from stdin and shows each in a 1280x720
"laptop screen" window, as if the person's browser had opened that page. Once
the window is on screen it prints ``REGION x,y,w,h`` (its client area, in
screen pixels) so the demo can confine Tripwire's warning to this window. It is a normal window, not
always-on-top, so Tripwire's warning overlay appears above it, exactly as it
would above a real scam page. Runs as its own process because Tk allows only
one GUI thread per process and the overlay needs one too.

Press Esc to close.
"""

from __future__ import annotations

import ctypes
import queue
import sys
import threading
import tkinter as tk

from PIL import Image, ImageTk


def main() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # cover the whole screen at any display scaling
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    root.title("Demo stage")
    root.configure(bg="black")
    root.geometry("1280x720+60+40")
    root.resizable(False, False)
    root.bind("<Escape>", lambda _e: root.destroy())
    label = tk.Label(root, bg="black")
    label.pack(fill="both", expand=True)
    paths: queue.Queue[str] = queue.Queue()

    def read_stdin() -> None:
        for line in sys.stdin:
            paths.put(line.strip())
        paths.put("")  # stdin closed: demo finished

    def poll() -> None:
        try:
            while True:
                path = paths.get_nowait()
                if not path:
                    root.destroy()
                    return
                w, h = root.winfo_width(), root.winfo_height()
                image = Image.open(path).convert("RGB").resize((w, h))
                label.image = ImageTk.PhotoImage(image)  # keep a reference
                label.configure(image=label.image)
        except queue.Empty:
            pass
        root.after(100, poll)

    def report_region() -> None:
        print(f"REGION {root.winfo_rootx()},{root.winfo_rooty()},{root.winfo_width()},{root.winfo_height()}", flush=True)

    threading.Thread(target=read_stdin, daemon=True).start()
    root.after(800, report_region)
    root.after(200, poll)
    root.mainloop()


if __name__ == "__main__":
    main()
