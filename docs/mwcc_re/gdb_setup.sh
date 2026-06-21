#!/bin/bash
# Reproducible dynamic-RE setup for mwcceppc.exe on x86_64 Ubuntu (no sudo required).
#
# The handover (HANDOVER_x86_ubuntu.md) was blocked on arm64 Mac because lldb could not
# break at the PE's flat VAs (Rosetta + wibo segment model). On NATIVE x86_64 Linux this
# works: wibo (an x86_64 ELF, loaded at 0x70000000+) maps the 32-bit PE at its image base
# 0x400000 and runs the guest in compatibility mode. A software breakpoint at a guest VA
# (e.g. 0x509010) hits normally; ptrace/gdb read the regs from the 64-bit user_regs_struct.
#
# This host had no gdb/sudo, so we fetch gdb + its libs as .debs and run from a local prefix.

set -e
PREFIX=/tmp/gdbpkg
mkdir -p "$PREFIX" && cd "$PREFIX"
for pkg in gdb libbabeltrace1 libipt2 libsource-highlight4t64 libdebuginfod1t64; do
  [ -e "$pkg"*.deb ] || apt-get download "$pkg"
done
for d in *.deb; do dpkg -x "$d" gdbroot; done
cat > /tmp/gdbrun.sh <<'EOF'
#!/bin/bash
export LD_LIBRARY_PATH=/tmp/gdbpkg/gdbroot/usr/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH
exec /tmp/gdbpkg/gdbroot/usr/bin/gdb "$@"
EOF
chmod +x /tmp/gdbrun.sh
echo "gdb ready: /tmp/gdbrun.sh"

# --- How to break at a guest VA -------------------------------------------------------
# gdb can't insert a guest-VA breakpoint at launch (PE not mapped yet). Break first at
# wibo's 64->32 mode-switch thunk `call_EntryProc`, THEN set the guest breakpoint:
#
#   break call_EntryProc      # PE is mapped once this hits
#   run
#   delete
#   break *0x509010           # ValueNumbering.c entry (guest VA)
#   continue
#
# Optimizer pass entry VAs (image base 0x400000), from assert_map_GC2.0.txt:
#   IroCSE.c            0x0046a360
#   IroPropagate.c      0x00470060
#   Coloring.c          0x00508680 0x00508900 0x00508c10
#   ValueNumbering.c    0x00509010   (runs ~96x per function — per-IR-node VN)
#   InterferenceGraph.c 0x0057b680 0x0057bad0
#
# Run mwcceppc DIRECTLY under wibo (sjiswrap is unnecessary unless the .c carries SJIS;
# dll_01CA_dimexplosion.c does not):
#   /tmp/gdbrun.sh -batch -x cmds.gdb --args build/tools/wibo \
#     build/compilers/GC/2.0/mwcceppc.exe <flags> -c <src.c> -o <outdir>/
# Get <flags> from: ninja -t commands <unit.o>  (drop the leading sjiswrap.exe arg).
#
# Isolation: the full TU compiles hundreds of functions, so 0x509010 fires thousands of
# times. To study ONE function's codegen, compile a standalone TU (see mini.c approach in
# the partial doc) — it reproduces the *fold* but NOT the exact whole-TU coloring.
