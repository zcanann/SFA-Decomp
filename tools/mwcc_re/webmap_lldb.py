import lldb
LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/4bc59d1c-c2ed-41ca-b666-098e234d3fe6/scratchpad/webmap.txt', 'w', buffering=1)
err = lldb.SBError()
_armed = [False]

def rd(proc, addr, n):
    b = proc.ReadMemory(addr, n, err)
    return b if b else None

def on_apply(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    op = frame.FindRegister('rdx').GetValueAsUnsigned() & 0xffffffff
    b = rd(proc, op + 4, 2)
    opcode = int.from_bytes(b, 'little') if b else -1
    inst = frame.FindRegister('rsi').GetValueAsUnsigned() & 0xffffffff
    raw = rd(proc, inst, 0x60)
    if raw is None: return False
    nops = int.from_bytes(raw[0x22:0x24], 'little')
    ops = []
    for i in range(min(nops, 5)):
        o = raw[0x24 + i*0xc: 0x24 + i*0xc + 8]
        ops.append(f'k{o[0]}c{o[1]}i{int.from_bytes(o[4:6], "little")}')
    LOG.write(f'I op={opcode} {" ".join(ops)}\n')
    return False

def on_bootstrap(frame, bp_loc, extra_args, internal_dict):
    if _armed[0]: return False
    _armed[0] = True
    target = frame.GetThread().GetProcess().GetTarget()
    bp = target.BreakpointCreateByAddress(0x508804)
    bp.SetScriptCallbackFunction('webmap_lldb.on_apply')
    bp.SetAutoContinue(True)
    LOG.write('==ARMED==\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName('_ZN4wibo10Executable14resolveImportsEv')
    bp.SetScriptCallbackFunction('webmap_lldb.on_bootstrap')
    bp.SetAutoContinue(True)
    result.PutCString('webmap set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f webmap_lldb.setup webmap_setup')
