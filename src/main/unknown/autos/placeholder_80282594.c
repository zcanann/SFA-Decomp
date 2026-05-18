#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282594.h"

extern int _GetInputValue(int obj, int buf, u8 a, u8 b);

/*
 * --INFO--
 *
 * Function: inpGetSurPanning
 * EN v1.0 Address: 0x80282588
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80282594
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int inpGetSurPanning(McmdVoiceState *state)
{
    int obj;
    int flags;

    obj = (int)state;
    flags = *(int *)(obj + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_SUR_PANNING) == 0) {
        return *(u16 *)(obj + 0x280);
    }
    *(int *)(obj + 0x214) = flags & ~MCMD_INPUT_DIRTY_SUR_PANNING;
    return _GetInputValue(obj, obj + 0x260, *(u8 *)(obj + 0x121), *(u8 *)(obj + 0x122));
}

/*
 * --INFO--
 *
 * Function: inpGetPitchBend
 * EN v1.0 Address: 0x802825D0
 * EN v1.0 Size: 72b
 */
int inpGetPitchBend(McmdVoiceState *state)
{
    int obj;
    int flags;

    obj = (int)state;
    flags = *(int *)(obj + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_PITCH_BEND) == 0) {
        return *(u16 *)(obj + 0x2a4);
    }
    *(int *)(obj + 0x214) = flags & ~MCMD_INPUT_DIRTY_PITCH_BEND;
    return _GetInputValue(obj, obj + 0x284, *(u8 *)(obj + 0x121), *(u8 *)(obj + 0x122));
}
