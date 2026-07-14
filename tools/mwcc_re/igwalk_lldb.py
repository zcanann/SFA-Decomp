import lldb
LOG = open('/private/tmp/claude-501/-Users-jackpriceburns-Code-sfa/4bc59d1c-c2ed-41ca-b666-098e234d3fe6/scratchpad/igwalk.txt', 'w', buffering=1)
err = lldb.SBError()
_armed = [False]

def rd(proc, addr, n):
    b = proc.ReadMemory(addr, n, err)
    return b if b else None

def on_desc(frame, bp_loc, extra_args, internal_dict):
    proc = frame.GetThread().GetProcess()
    esp = frame.GetSP()
    b = rd(proc, esp + 0xc, 4)
    if not b: return False
    desc = int.from_bytes(b, 'little')
    db = rd(proc, desc, 0x2a)
    if db:
        n22 = int.from_bytes(db[0x22:0x24], 'little')
        f24 = db[0x24]; cls = db[0x25]
        w26 = int.from_bytes(db[0x26:0x28], 'little')
        w28 = int.from_bytes(db[0x28:0x2a], 'little')
        LOG.write(f'D n={n22} f=0x{f24:02x} c={cls} w{w26} w{w28}\n')
    return False

def on_bootstrap(frame, bp_loc, extra_args, internal_dict):
    if _armed[0]: return False
    _armed[0] = True
    target = frame.GetThread().GetProcess().GetTarget()
    bp = target.BreakpointCreateByAddress(0x57b7f3)
    bp.SetScriptCallbackFunction('igwalk_lldb.on_desc')
    bp.SetAutoContinue(True)
    LOG.write('==ARMED==\n')
    return False

def setup(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    bp = target.BreakpointCreateByName('_ZN4wibo10Executable14resolveImportsEv')
    bp.SetScriptCallbackFunction('igwalk_lldb.on_bootstrap')
    bp.SetAutoContinue(True)
    result.PutCString('igwalk set')

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f igwalk_lldb.setup igwalk_setup')
