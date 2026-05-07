#include "ghidra_import.h"

/*
 * inpSetMidiCtrl - combined RPN/MIDI controller setter. Reference
 * projects split the RPN cases into separate symbols, but this retail
 * function is one fall-through body in SFA. Stubbed.
 */
#pragma dont_inline on
void inpSetMidiCtrl(u8 idx, u8 a, u8 b, u8 mask)
{
    (void)idx; (void)a; (void)b; (void)mask;
}
#pragma dont_inline reset

/*
 * inpSetMidiCtrl14 - wrapper that splits a 16-bit data word into two
 * byte halves and dispatches to the MIDI-control setter. Stubbed.
 */
#pragma dont_inline on
void inpSetMidiCtrl14(u8 idx, u8 a, u8 b, u32 data)
{
    (void)idx; (void)a; (void)b; (void)data;
}
#pragma dont_inline reset
