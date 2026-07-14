import lldb

LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/4bc59d1c-c2ed-41ca-b666-098e234d3fe6/scratchpad/pri_trace.txt', 'w', buffering=1)
err = lldb.SBError()

def rd(proc, addr, n):
    b = proc.ReadMemory(addr, n, err)
    return b if b else None

def on_commit(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    desc = frame.FindRegister('rbx').GetValueAsUnsigned() & 0xffffffff
    d = rd(proc, desc, 0x2a)
    pri = int.from_bytes(d[4:8], 'little', signed=True)
    flags = d[0x24]
    cls = d[0x25]
    b = rd(proc, 0x5e9b04 + cls * 4, 4)
    idx = int.from_bytes(b, 'little')
    LOG.write(f'N cls={cls} idx={idx} pri={pri} flags=0x{flags:02x}\n')
    return False

_armed = [False]
def on_bootstrap(frame, bp_loc, extra_args, internal_dict):
    if _armed[0]: return False
    _armed[0] = True
    target = frame.GetThread().GetProcess().GetTarget()
    bp = target.BreakpointCreateByAddress(0x4fe563)
    bp.SetScriptCallbackFunction('pri_trace_lldb.on_commit')
    bp.SetAutoContinue(True)
    LOG.write('==ARMED==\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName('_ZN4wibo10Executable14resolveImportsEv')
    bp.SetScriptCallbackFunction('pri_trace_lldb.on_bootstrap')
    bp.SetAutoContinue(True)
    result.PutCString('pri trace set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f pri_trace_lldb.setup pri_trace_setup')
