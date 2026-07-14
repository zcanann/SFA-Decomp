import lldb, math
LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/4bc59d1c-c2ed-41ca-b666-098e234d3fe6/scratchpad/adj.txt', 'w', buffering=1)
err = lldb.SBError()
_armed = [False]

def on_bit(frame, bp_loc, extra_args, internal_dict):
    esi = frame.FindRegister('rsi').GetValueAsUnsigned() & 0xffffffff
    ecx = frame.FindRegister('rcx').GetValueAsUnsigned() & 0x1f
    idx = esi*32 + ecx
    hi = int((math.isqrt(8*idx+1)-1)//2)
    while (hi*hi)>>1 > idx: hi -= 1
    while ((hi+1)*(hi+1))>>1 <= idx: hi += 1
    lo = idx - ((hi*hi)>>1)
    LOG.write(f'E {hi} {lo}\n')
    return False

def on_bootstrap(frame, bp_loc, extra_args, internal_dict):
    if _armed[0]: return False
    _armed[0] = True
    target = frame.GetThread().GetProcess().GetTarget()
    for addr in (0x57b9ee, 0x57ba0d, 0x57bccc, 0x57bced):
        bp = target.BreakpointCreateByAddress(addr)
        bp.SetScriptCallbackFunction('adj_lldb.on_bit')
        bp.SetAutoContinue(True)
    LOG.write('==ARMED==\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName('_ZN4wibo10Executable14resolveImportsEv')
    bp.SetScriptCallbackFunction('adj_lldb.on_bootstrap')
    bp.SetAutoContinue(True)
    result.PutCString('adj set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f adj_lldb.setup adj_setup')
