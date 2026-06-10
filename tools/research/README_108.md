# #108 dose-inversion minimal harness (research)

e14.c — the canonical E14 shape (params + 2 call-crossing copies + 2
multi-def webs): colors params r25-r27 (bottom), copies r31/r30,
multi-defs r29/r28 (E1 descending creation).

e14_div.c — same with ONE magic-const division (`md2 = p3 / 7`): the
interleave FULLY INVERTS (params r29-r31 TOP, copies/multi-defs sink to
r28-r25). A const-folded `600 / 7` control stays canonical — the dose is
the RUNTIME division's IR, not the source text.

Compile (GC/2.0, unit flags):
  build/tools/wibo build/compilers/GC/2.0/mwcceppc.exe -nodefaults -proc gekko \
    -align powerpc -enum int -fp hardware -Cpp_exceptions off -O4,p -inline auto \
    -maxerrors 1 -nosyspath -RTTI off -fp_contract on -str reuse \
    -opt nopeephole,noschedule -lang=c -c e14_div.c -o e14_div.o
Read the `mr r2N,r3/r4/r5` prologue lines for the coloring.

Open questions (next session):
1. ONE f32 conversion did NOT shift this harness (sub-threshold?) — find
   the conversion count threshold here; the campaign saw 1-2 convs = one rank.
2. The timer probe is dose-INSENSITIVE entirely — diff its web structure
   against e14 to find the arming condition's precise form.
3. The one-law hypothesis: is target ALWAYS E1-canonical with doses, and
   every "rotation" fn a case where OUR IR carries a different dose than
   the original's (same instrs, different IR-internal census)? If so the
   fix per fn = find the import construct whose IR differs (CONCAT44
   blobs, division spellings, conversion node counts) without changing
   the instruction stream.
