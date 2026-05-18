#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80282630.h"

extern u16 _GetInputValue(McmdVoiceState *state, McmdInputSlot *slot, u8 a, u8 b);

/*
 * --INFO--
 *
 * Function: inpGetDoppler
 * EN v1.0 Address: 0x80282618
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80282630
 * EN v1.1 Size: 72b
 */
u16 inpGetDoppler(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_DOPPLER) == 0) {
        return *(u16 *)(rawState + 0x2c8);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_DOPPLER;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x2a8),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}

/*
 * Function: inpGetModulation
 */
u16 inpGetModulation(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_MODULATION) == 0) {
        return *(u16 *)(rawState + 0x2ec);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_MODULATION;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x2cc),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}

/*
 * Function: inpGetPedal
 */
u16 inpGetPedal(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_PEDAL) == 0) {
        return *(u16 *)(rawState + 0x310);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_PEDAL;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x2f0),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}

/*
 * Function: inpGetPreAuxA
 */
u16 inpGetPreAuxA(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_A) == 0) {
        return *(u16 *)(rawState + 0x358);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_A;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x338),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}

/*
 * Function: inpGetReverb
 */
u16 inpGetReverb(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_REVERB) == 0) {
        return *(u16 *)(rawState + 0x37c);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_REVERB;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x35c),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}

/*
 * Function: inpGetPreAuxB
 */
u16 inpGetPreAuxB(McmdVoiceState *state)
{
    int rawState = (int)state;
    u32 flags = *(u32 *)(rawState + 0x214);
    if ((flags & MCMD_INPUT_DIRTY_PRE_AUX_B) == 0) {
        return *(u16 *)(rawState + 0x3a0);
    }
    *(u32 *)(rawState + 0x214) = flags & ~MCMD_INPUT_DIRTY_PRE_AUX_B;
    return _GetInputValue(state, (McmdInputSlot *)(rawState + 0x380),
                       *(u8 *)(rawState + 0x121), *(u8 *)(rawState + 0x122));
}
