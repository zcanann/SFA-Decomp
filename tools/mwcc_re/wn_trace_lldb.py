"""Web-numbering tracer for MWCC GC/2.0 (mwcceppc.exe under wibo).

Logs every webIndex commit (0x4fe550, bp at 0x4fe563) as:
    N cls=<class> idx=<webIndex> pri=<pri> fl=<flags> obj=<addr> name=<name> site=<band>
plus a marker per function reset (0x4fe610). `site` is decoded from the real
return address ra2=[esp+56] and names the numbering band (see
docs/mwcc_re/INVESTIGATION_web_numbering_decode.md sections 3-5). ra1=[esp+24]
must always read 0x4d0556; anything else means the frame layout assumption broke.

PREREQUISITES (see INVESTIGATION_web_numbering_decode.md section 8):
  1. `sudo DevToolsSecurity -enable` -- REQUIRED. Without developer mode, lldb
     hangs forever on launch and "lost connection" on attach, for native arm64
     targets too. Must be run by a human (admin + system security setting).
  2. A wibo copy signed with com.apple.security.get-task-allow. The shipped
     build/tools/wibo is unsigned and cannot be debugged. Never sign the shared
     copy in place -- lanes share the working tree.

Usage:
    WN_TRACE_LOG=/path/out.txt lldb --batch \
      -o 'command script import tools/mwcc_re/wn_trace_lldb.py' \
      -o 'wn_trace_setup' -o run -o quit -- \
      /path/wibo_dbg build/compilers/GC/2.0/mwcceppc.exe <cflags -lang=c> \
      -c probe.c -o out/

Validate against a known-answer function before trusting any new reading.
"""

import os
import lldb

LOG = open(os.environ.get('WN_TRACE_LOG', '/tmp/wn_trace.txt'), 'w', buffering=1)
err = lldb.SBError()

SITES = {
    0x435d7c: 'L1_prescan',
    0x435dde: 'L2_LOCALS',
    0x435e4a: 'L3_tempA',
    0x435eba: 'L4_tempAT',
    0x435ef3: 'L5_TOC',
}

COMMIT_BP = 0x4fe563
RESET_BP = 0x4fe610
WEBEND = 0x5e9b04
RA1_EXPECTED = 0x4d0556


def rd(p, a, n):
    b = p.ReadMemory(a, n, err)
    return b if b else None


def cstr(p, a, maxn=64):
    if not a or a > 0xffffffff:
        return ''
    out = b''
    for i in range(maxn):
        c = rd(p, a + i, 1)
        if not c or c == b'\x00':
            break
        out += c
    try:
        return out.decode('latin-1')
    except Exception:
        return ''


def on_commit(frame, bl, ea, d_):
    p = frame.GetThread().GetProcess()
    desc = frame.FindRegister('rbx').GetValueAsUnsigned() & 0xffffffff
    d = rd(p, desc, 0x2a)
    if not d:
        return False
    pri = int.from_bytes(d[4:8], 'little', signed=True)
    flags = d[0x24]
    cls = d[0x25]
    ib = rd(p, WEBEND + cls * 4, 4)
    if not ib:
        return False
    idx = int.from_bytes(ib, 'little')
    sp = frame.GetSP()

    def dw(off):
        b = rd(p, sp + off, 4)
        return int.from_bytes(b, 'little') if b else 0

    obj = dw(28)
    ra1 = dw(24)
    ra2 = dw(56)
    nb = rd(p, obj + 0xa, 4)
    namep = int.from_bytes(nb, 'little') if nb else 0
    nm = cstr(p, namep) or cstr(p, namep + 8)
    site = SITES.get(ra2, 'ra2=0x%x' % ra2)
    warn = '' if ra1 == RA1_EXPECTED else '  !!RA1_UNEXPECTED'
    LOG.write('N cls=%d idx=%d pri=%d fl=0x%02x obj=0x%x name=%r site=%s ra1=0x%x%s\n'
              % (cls, idx, pri, flags, obj, nm, site, ra1, warn))
    return False


def on_reset(frame, bl, ea, d_):
    LOG.write('==== FUNC RESET ====\n')
    return False


_armed = [False]


def on_boot(frame, bl, ea, d_):
    if _armed[0]:
        return False
    _armed[0] = True
    t = frame.GetThread().GetProcess().GetTarget()
    for addr, fn in ((COMMIT_BP, 'wn_trace_lldb.on_commit'),
                     (RESET_BP, 'wn_trace_lldb.on_reset')):
        bp = t.BreakpointCreateByAddress(addr)
        bp.SetScriptCallbackFunction(fn)
        bp.SetAutoContinue(True)
    LOG.write('==ARMED==\n')
    return False


def setup(dbg, cmd, res, d_):
    t = dbg.GetSelectedTarget()
    bp = t.BreakpointCreateByName('_ZN4wibo10Executable14resolveImportsEv')
    bp.SetScriptCallbackFunction('wn_trace_lldb.on_boot')
    bp.SetAutoContinue(True)
    res.PutCString('armed')


def __lldb_init_module(dbg, d_):
    dbg.HandleCommand('command script add -f wn_trace_lldb.setup wn_trace_setup')
