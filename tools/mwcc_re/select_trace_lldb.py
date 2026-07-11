import lldb

LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/5fd8f3f9-fe4b-4c4e-9077-d2bcc5827257/scratchpad/select_trace.txt', 'w')
err = lldb.SBError()

def rd8(proc, addr):
    b = proc.ReadMemory(addr, 1, err)
    return b[0] if b else -1

def rd16(proc, addr):
    b = proc.ReadMemory(addr, 2, err)
    return int.from_bytes(b, 'little') if b else -1

def rd32(proc, addr):
    b = proc.ReadMemory(addr, 4, err)
    return int.from_bytes(b, 'little') if b else -1

def reg(frame, name):
    return frame.FindRegister(name).GetValueAsUnsigned()

def on_driver(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    cls = rd8(proc, 0x5ea299)
    LOG.write(f'==DRIVER cls={cls}==\n')
    return False

def on_assign(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    cls = rd8(proc, 0x5ea299)
    web = reg(frame, 'rbx') & 0xffffffff
    idx = rd16(proc, web + 0x10)
    nadj = rd16(proc, web + 0x18)
    r = reg(frame, 'rcx') & 0xffffffff
    LOG.write(f'A cls={cls} idx={idx} nadj={nadj} reg={r}\n')
    return False

def on_fallback(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    cls = rd8(proc, 0x5ea299)
    web = reg(frame, 'rbx') & 0xffffffff
    idx = rd16(proc, web + 0x10)
    nadj = rd16(proc, web + 0x18)
    r = reg(frame, 'rax') & 0xffffffff
    LOG.write(f'F cls={cls} idx={idx} nadj={nadj} reg={r}\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    for addr, fn in ((0x508680, 'on_driver'), (0x50899e, 'on_assign'), (0x5089c4, 'on_fallback')):
        bp = target.BreakpointCreateByAddress(addr)
        bp.SetScriptCallbackFunction(f'mwcc_trace.{fn}')
        bp.SetAutoContinue(True)
    result.PutCString('trace breakpoints set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f mwcc_trace.setup mwcc_trace_setup')
