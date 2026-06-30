#include "main/audio/inp_ctrl.h"
#include "main/audio/synth_scale.h"
extern u32 sndRandSeed;
extern s16 sndSintab[];

/*
 * Bit-11 (0x800) accessor - slot at +0x3a4, cached u16 at +0x3c4.
 *
 * EN v1.1 Address: 0x802827C8, size 72b
 */
extern u8 lbl_803BDA74[];
extern u8 lbl_803BDEF4[];
extern u32 lbl_803D3CA0[];
extern u32 lbl_8032FFE0[];
extern u32 lbl_8032FFF0[];

u16 inpGetPostAuxB(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_POST_AUX_B) == 0)
    {
        return state->postAuxBInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_POST_AUX_B;
    return _GetInputValue(state, &state->postAuxBInput, state->midiSlot, state->midiEvent);
}

/*
 * Bit-12 (0x1000) accessor - slot at +0x3c8, cached u16 at +0x3e8.
 *
 * EN v1.1 Address: 0x80282810, size 72b
 */
u16 inpGetTremolo(McmdVoiceState* state)
{
    u32 flags = state->inputDirtyFlags;
    if ((flags & MCMD_INPUT_DIRTY_TREMOLO) == 0)
    {
        return state->tremoloInput.cachedValue;
    }
    state->inputDirtyFlags = flags & ~MCMD_INPUT_DIRTY_TREMOLO;
    return _GetInputValue(state, &state->tremoloInput, state->midiSlot, state->midiEvent);
}

/*
 * Cached aux A input getter for a studio/channel/slot.
 */
u16 inpGetAuxA(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 maskedFlags;
    u32 isDirty;
    u32* dirtyWord;

    mask = lbl_8032FFE0[channel & 0xff];
    dirtyWord = (u32*)((u8*)lbl_803D3CA0 + ((handleIndex & 0xff) << 6) + ((auxIndex & 0xff) << 2));
    flags = *dirtyWord;
    maskedFlags = flags & mask;
    isDirty = !!maskedFlags;
    if (isDirty != 0)
    {
        *dirtyWord = flags & ~mask;
    }
    if (isDirty == 0)
    {
        return *(u16*)(lbl_803BDEF4 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24 + 0x20);
    }
    return _GetInputValue(0,
                          (McmdInputSlot*)(lbl_803BDEF4 + (studio & 0xff) * 0x90 +
                              (channel & 0xff) * 0x24),
                          auxIndex, handleIndex);
}

/*
 * Cached aux B input getter for a studio/channel/slot.
 */
u16 inpGetAuxB(u32 studio, u32 channel, u32 auxIndex, u32 handleIndex)
{
    u32 flags;
    u32 mask;
    u32 maskedFlags;
    u32 isDirty;
    u32* dirtyWord;

    mask = lbl_8032FFF0[channel & 0xff];
    dirtyWord = (u32*)((u8*)lbl_803D3CA0 + ((handleIndex & 0xff) << 6) + ((auxIndex & 0xff) << 2));
    flags = *dirtyWord;
    maskedFlags = flags & mask;
    isDirty = !!maskedFlags;
    if (isDirty != 0)
    {
        *dirtyWord = flags & ~mask;
    }
    if (isDirty == 0)
    {
        return *(u16*)(lbl_803BDA74 + (studio & 0xff) * 0x90 + (channel & 0xff) * 0x24 + 0x20);
    }
    return _GetInputValue(0,
                          (McmdInputSlot*)(lbl_803BDA74 + (studio & 0xff) * 0x90 +
                              (channel & 0xff) * 0x24),
                          auxIndex, handleIndex);
}

/*
 * inpInit - input/controller state init.
 *
 * EN v1.0 Address: 0x802829D0
 * EN v1.0 Size: 740b (0x2E4)
 */
void inpInit(u32 state)
{
    McmdVoiceState* vs = (McmdVoiceState*)state;

    if (state != 0)
    {
        vs->volumeInput.entries[0].controller = MCMD_CTRL_VOLUME;
        vs->volumeInput.entries[0].combineModeFlags = 0;
        vs->volumeInput.entries[0].scale = 0x10000;
        vs->volumeInput.entries[1].controller = MCMD_CTRL_EXPRESSION;
        vs->volumeInput.entries[1].combineModeFlags = 2;
        vs->volumeInput.entries[1].scale = 0x10000;
        vs->volumeInput.entryCount = 2;
        vs->panningInput.entries[0].controller = MCMD_CTRL_PANNING;
        vs->panningInput.entries[0].combineModeFlags = 0;
        vs->panningInput.entries[0].scale = 0x10000;
        vs->panningInput.entryCount = 1;
        vs->surPanningInput.entries[0].controller = MCMD_CTRL_SUR_PANNING;
        vs->surPanningInput.entries[0].combineModeFlags = 0;
        vs->surPanningInput.entries[0].scale = 0x10000;
        vs->surPanningInput.entryCount = 1;
        vs->pitchBendInput.entries[0].controller = MCMD_CTRL_PITCH_BEND;
        vs->pitchBendInput.entries[0].combineModeFlags = 0;
        vs->pitchBendInput.entries[0].scale = 0x10000;
        vs->pitchBendInput.entryCount = 1;
        vs->modulationInput.entries[0].controller = MCMD_CTRL_MODULATION;
        vs->modulationInput.entries[0].combineModeFlags = 0;
        vs->modulationInput.entries[0].scale = 0x10000;
        vs->modulationInput.entryCount = 1;
        vs->pedalInput.entries[0].controller = MCMD_CTRL_PEDAL;
        vs->pedalInput.entries[0].combineModeFlags = 0;
        vs->pedalInput.entries[0].scale = 0x10000;
        vs->pedalInput.entryCount = 1;
        vs->portamentoInput.entries[0].controller = MCMD_CTRL_PORTAMENTO;
        vs->portamentoInput.entries[0].combineModeFlags = 0;
        vs->portamentoInput.entries[0].scale = 0x10000;
        vs->portamentoInput.entryCount = 1;
        vs->preAuxAInput.entryCount = 0;
        vs->reverbInput.entries[0].controller = MCMD_CTRL_REVERB;
        vs->reverbInput.entries[0].combineModeFlags = 0;
        vs->reverbInput.entries[0].scale = 0x10000;
        vs->reverbInput.entryCount = 1;
        vs->preAuxBInput.entryCount = 0;
        vs->postAuxBInput.entries[0].controller = MCMD_CTRL_POST_AUX_B;
        vs->postAuxBInput.entries[0].combineModeFlags = 0;
        vs->postAuxBInput.entries[0].scale = 0x10000;
        vs->postAuxBInput.entryCount = 1;
        vs->dopplerInput.entries[0].controller = MCMD_CTRL_DOPPLER;
        vs->dopplerInput.entries[0].combineModeFlags = 0;
        vs->dopplerInput.entries[0].scale = 0x10000;
        vs->dopplerInput.entryCount = 1;
        vs->tremoloInput.entryCount = 0;
        vs->inputDirtyFlags = MCMD_INPUT_DIRTY_ALL;
        vs->exCtrlDirty[0] = 0;
        vs->exCtrlDirty[1] = 0;
        vs->unkA8[0] = 0;
    }
    else
    {
        int i;
        u8* b = lbl_803BDA74;
        u8* a = lbl_803BDEF4;
        u32* p = lbl_803D3CA0;

        a[0x22] = 0;
        b[0x22] = 0;
        a[0x46] = 0;
        b[0x46] = 0;
        a[0x6a] = 0;
        b[0x6a] = 0;
        a[0x8e] = 0;
        b[0x8e] = 0;
        a[0xb2] = 0;
        b[0xb2] = 0;
        a[0xd6] = 0;
        b[0xd6] = 0;
        a[0xfa] = 0;
        b[0xfa] = 0;
        a[0x11e] = 0;
        b[0x11e] = 0;
        a[0x142] = 0;
        b[0x142] = 0;
        a[0x166] = 0;
        b[0x166] = 0;
        a[0x18a] = 0;
        b[0x18a] = 0;
        a[0x1ae] = 0;
        b[0x1ae] = 0;
        a[0x1d2] = 0;
        b[0x1d2] = 0;
        a[0x1f6] = 0;
        b[0x1f6] = 0;
        a[0x21a] = 0;
        b[0x21a] = 0;
        a[0x23e] = 0;
        b[0x23e] = 0;
        a[0x262] = 0;
        b[0x262] = 0;
        a[0x286] = 0;
        b[0x286] = 0;
        a[0x2aa] = 0;
        b[0x2aa] = 0;
        a[0x2ce] = 0;
        b[0x2ce] = 0;
        a[0x2f2] = 0;
        b[0x2f2] = 0;
        a[0x316] = 0;
        b[0x316] = 0;
        a[0x33a] = 0;
        b[0x33a] = 0;
        a[0x35e] = 0;
        b[0x35e] = 0;
        a[0x382] = 0;
        b[0x382] = 0;
        a[0x3a6] = 0;
        b[0x3a6] = 0;
        a[0x3ca] = 0;
        b[0x3ca] = 0;
        a[0x3ee] = 0;
        b[0x3ee] = 0;
        a[0x412] = 0;
        b[0x412] = 0;
        a[0x436] = 0;
        b[0x436] = 0;
        a[0x45a] = 0;
        b[0x45a] = 0;
        a[0x47e] = 0;
        b[0x47e] = 0;

        for (i = 0; i < 8; i++)
        {
            u32* row = p + i * 16;
            row[0] = 0xff;
            row[1] = 0xff;
            row[2] = 0xff;
            row[3] = 0xff;
            row[4] = 0xff;
            row[5] = 0xff;
            row[6] = 0xff;
            row[7] = 0xff;
            row[8] = 0xff;
            row[9] = 0xff;
            row[10] = 0xff;
            row[11] = 0xff;
            row[12] = 0xff;
            row[13] = 0xff;
            row[14] = 0xff;
            row[15] = 0xff;
        }
    }
}

/*
 * Map an input byte (0x80..0x88) to a packed table value via a
 * jumptable, falling through for inputs outside that range.
 *
 * EN v1.1 Address: 0x80282CB4, size 112b
 */
#pragma dont_inline on
u32 inpTranslateExCtrl(u32 input)
{
    u32 value = input & 0xff;
    u32 idx = value - 0x80;
    switch (idx)
    {
    case 0: return MCMD_CTRL_PITCH_BEND;
    case 1: return 0x82;
    case 2: return MCMD_CTRL_EX_A0;
    case 3: return MCMD_CTRL_EX_A1;
    case 4: return MCMD_CTRL_SUR_PANNING;
    case 5: return MCMD_CTRL_DOPPLER;
    case 6: return MCMD_CTRL_MIDI_LAYER;
    case 7: return MCMD_CTRL_VOICE_AGE;
    case 8: return 0xa4;
    default: return input;
    }
}
#pragma dont_inline reset

/*
 * Read an extended controller value, with local state-backed overrides for
 * translated controller 0xA0/0xA1.
 */
u32 inpGetExCtrl(McmdVoiceState* state, u32 ctrl)
{
    int translated;
    u16 value;

    translated = inpTranslateExCtrl(ctrl) & 0xff;
    switch (translated)
    {
    case MCMD_CTRL_EX_A0:
        return state->exCtrlA0Value * 2 + 0x2000;
    case MCMD_CTRL_EX_A1:
        return state->exCtrlA1Value * 2 + 0x2000;
    default:
        if (state->midiSlot != 0xff)
        {
            extern u32 inpGetMidiCtrl(u32 controller, u32 slot, u32 key);
            value = inpGetMidiCtrl(ctrl, state->midiSlot, state->midiEvent) & 0xffff;
        }
        else
        {
            value = 0;
        }
        return value & 0xffff;
    }
}

/*
 * Clamp and write an extended controller through MIDI for non-local controls.
 */
void inpSetExCtrl(McmdVoiceState* state, u32 ctrl, s16 value)
{
    int translated;
    int clamped;
    s16 v;

    if (value < 0)
    {
        clamped = 0;
    }
    else if (value > 0x3fff)
    {
        clamped = 0x3fff;
    }
    else
    {
        clamped = value;
    }
    v = clamped;
    translated = inpTranslateExCtrl(ctrl) & 0xff;
    if ((translated >= MCMD_CTRL_MIDI_LAYER || translated < MCMD_CTRL_EX_A0) &&
        state->midiSlot != 0xff)
    {
        inpSetMidiCtrl14(ctrl, state->midiSlot, state->midiEvent, v);
    }
}

/*
 * Pseudo-random number generator (linear congruential).
 *
 * EN v1.1 Address: 0x80282E5C, size 32b
 */
u16 sndRand(void)
{
    sndRandSeed = sndRandSeed * 0xA8351D63U;
    return (u16)((sndRandSeed >> 6) & 0xffff);
}

/*
 * Look up s16 from a 4-zone table based on the input's low 12 bits.
 * Upper two zones return sign-flipped values.
 *
 * EN v1.1 Address: 0x80282E7C, size 108b
 */
s16 sndSin(u32 packed)
{
    s16* table = sndSintab;
    u32 zone = packed & 0xfff;
    if (zone < 0x400)
    {
        return table[zone];
    }
    if (zone < 0x800)
    {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return table[idx];
    }
    if (zone < 0xc00)
    {
        u32 idx = (zone & 0x3ff);
        return -table[idx];
    }
    {
        u32 idx = 0x3ff - (zone & 0x3ff);
        return -table[idx];
    }
}

/*
 * Binary search over fixed-stride sorted table entries.
 */
void* sndBSearch(void* key, void* base, int count, u32 stride, int (*cmp)(void*, void*))
{
    int high;
    int low;
    int mid;
    void* entry;
    int result;

    if (count != 0)
    {
        low = 1;
        high = count;
        do
        {
            mid = (low + high) >> 1;
            entry = (u8*)base + stride * (mid - 1);
            result = cmp(key, entry);
            if (result == 0)
            {
                return entry;
            }
            if (result < 0)
            {
                high = mid - 1;
            }
            else
            {
                low = mid + 1;
            }
        }
        while (low <= high);
    }
    return 0;
}

/*
 * Shift the value at *p left by 8 bits.
 *
 * EN v1.1 Address: 0x80282F80, size 16b
 */
void sndConvertMs(u32* p)
{
    *p = *p << 8;
}

/*
 * Compute a normalized scaled-1000-divided-by-32 value at *p using a
 * helper-derived divisor.
 *
 * EN v1.1 Address: 0x80282F90, size 72b
 */
void sndConvertTicks(u32* p, int x)
{
    int div = synthGetVoiceSlotChannelScale(x);
    *p = (((*p << 16) / div) * 0x3e8) >> 5;
}

/*
 * Right-shift by 8 (truncate ramp index).
 *
 * EN v1.1 Address: 0x80282FD8, size 8b
 */
u32 sndConvert2Ms(u32 x)
{
    return x >> 8;
}
