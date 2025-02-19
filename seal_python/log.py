from typing import Optional as Opt

debug = False
debug_head = ""
MAX_LEN = 160

def set_debug(debug_b: bool):
    global debug
    debug = debug_b

def log(msg: str):
    if not debug: return
    full_msg = debug_head + msg
    if len(full_msg) > MAX_LEN:
        full_msg = full_msg[:MAX_LEN-3]+"..."
    print(full_msg)
    
def log_h(head: Opt[str]=None):
    global debug_head
    debug_head = head if head is not None else ""
