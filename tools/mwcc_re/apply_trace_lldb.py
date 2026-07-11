import lldb
LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/5fd8f3f9-fe4b-4c4e-9077-d2bcc5827257/scratchpad/apply_trace.txt', 'w', buffering=1)
err = lldb.SBError()

def rd(proc, addr, n):
    b = proc.ReadMemory(addr, n, err)
    return b if b else None

def on_apply(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    op = frame.FindRegister('rdx').GetValueAsUnsigned() & 0xffffffff
    b = rd(proc, op + 4, 2)
    idx = int.from_bytes(b, 'little') if b else -1
    if idx == 72:
        inst = frame.FindRegister('rsi').GetValueAsUnsigned() & 0xffffffff
        raw = rd(proc, inst, 0x60)
        nops = int.from_bytes(raw[0x22:0x24], 'little')
        ops = []
        for i in range(min(nops, 5)):
            o = raw[0x24 + i*0xc: 0x24 + i*0xc + 8]
            ops.append(f'k{o[0]}c{o[1]}i{int.from_bytes(o[4:6], "little")}')
        LOG.write(f'idx72 inst=0x{inst:08x} raw16={raw[:0x22].hex()} nops={nops} ops={ops}\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByAddress(0x508804)
    bp.SetScriptCallbackFunction('apply_trace.on_apply')
    bp.SetAutoContinue(True)
    result.PutCString('apply trace set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f apply_trace.setup apply_trace_setup')
