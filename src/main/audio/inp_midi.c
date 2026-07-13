#include "main/audio/inp_midi.h"
#include "main/audio/mcmd.h"
#include "string.h"

#pragma exceptions on

typedef struct InpMidiState
{
    u8 pad0[0xC0];
    u8 midiCtrl[8][16][134]; /* 0x00C0 */
    u8 fxCtrl[16][134];      /* 0x43C0 */
} InpMidiState;

/*
 * Push an event onto a 4-slot ring at obj+0x22. Resets counter when
 * the flags byte is zero. Slot layout: [ctrl, flags|0x10 or translated
 * ctrl, _, _, value, _, _, _].
 */
typedef struct InpCtrlRing
{
    struct
    {
        u8 ctrl;  /* 0x0 */
        u8 flags; /* 0x1 */
        u8 pad[2];
        int value; /* 0x4 */
    } slots[4];    /* 0x00 */
    u8 pad20[2];   /* 0x20 */
    u8 count;      /* 0x22 */
} InpCtrlRing;

extern u8 sInpMidiCtrlFullResetPreset[];
extern u8 sInpMidiCtrlMaskedResetPreset[];
extern u8 lbl_803CD760[][INP_MIDI_SLOT_COUNT];
extern u8 gInpMidiLastNote[];
extern u8 gInpMidiCtrlByKey[];
extern u8 gInpMidiCtrl[];
extern u8 gInpChannelDefaultsByKey[][INP_MIDI_SLOT_COUNT];
extern u8 gInpChannelDefaults[];
extern int inpTranslateExCtrl(int input);

/*
 * Reset a MIDI-controller/default table from one of two preset banks,
 * then mark the last-note/controller slot dirty via inpSetMidiLastNote.
 */
void inpResetMidiCtrl(u8 channel, u8 key, u32 mode)
{
    u8* dst;
    u8* src;

    src = (mode != 0) ? sInpMidiCtrlFullResetPreset : sInpMidiCtrlMaskedResetPreset;

    if (key != INP_INVALID_SLOT)
    {
        dst = gInpMidiCtrlByKey + key * INP_MIDI_KEY_STRIDE + channel * INP_MIDI_CTRL_BANK_SIZE;
    }
    else
    {
        dst = gInpMidiCtrl + channel * INP_MIDI_CTRL_BANK_SIZE;
    }

    if (mode != 0)
    {
        memcpy(dst, src, 0x86);
    }
    else
    {
        int i;
        for (i = 0; i < 0x86; i++)
        {
            if (src[i] != 0xff)
            {
                dst[i] = src[i];
            }
        }
    }

    inpSetMidiLastNote(channel, key, 0xff);
}

/*
 * Read a 14-bit MIDI controller value from either the global channel defaults
 * or the per-key controller bank.
 */
u16 inpGetMidiCtrl(u8 controller, u8 slot, u8 key)
{
    InpMidiState* st;

    st = (InpMidiState*)lbl_803CD760;
    if (slot != INP_INVALID_SLOT)
    {
        if (key != INP_INVALID_SLOT)
        {
            if (controller < 0x40)
            {
                return st->midiCtrl[key][slot][controller & 0x1f] << 7 |
                       st->midiCtrl[key][slot][(controller & 0x1f) + 0x20];
            }
            if (controller < 0x46)
            {
                return (st->midiCtrl[key][slot][controller] < 0x40) ? 0 : 0x3fff;
            }
            if (controller >= 0x60 && controller < 0x66)
            {
                return 0;
            }
            if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
            {
                return (st->midiCtrl[key][slot][controller & 0xfe] << 7) |
                             st->midiCtrl[key][slot][(controller & 0xfe) + 1];
            }
            if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
            {
                return (st->midiCtrl[key][slot][controller & 0xfe] << 7) |
                             st->midiCtrl[key][slot][(controller & 0xfe) + 1];
            }
            return st->midiCtrl[key][slot][controller] << 7;
        }

        if (controller < 0x40)
        {
            return (st->fxCtrl[slot][controller & 0x1f] << 7) | st->fxCtrl[slot][(controller & 0x1f) + 0x20];
        }
        if (controller < 0x46)
        {
            return (st->fxCtrl[slot][controller] < 0x40) ? 0 : 0x3fff;
        }
        if (controller >= 0x60 && controller < 0x66)
        {
            return 0;
        }
        if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
        {
            return (st->fxCtrl[slot][controller & 0xfe] << 7) |
                         st->fxCtrl[slot][(controller & 0xfe) + 1];
        }
        if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
        {
            return (st->fxCtrl[slot][controller & 0xfe] << 7) |
                         st->fxCtrl[slot][(controller & 0xfe) + 1];
        }
        return st->fxCtrl[slot][controller] << 7;
    }
    return 0;
}

/*
 * Returns pointer into either 1D or 2D voice-state table.
 */
u8* inpGetChannelDefaults(u8 channel, u8 key)
{
    if (key == INP_INVALID_SLOT)
    {
        return &gInpChannelDefaults[channel];
    }
    return &gInpChannelDefaultsByKey[key][channel];
}

/*
 * Stores 2 into voice-state slot (1D or 2D variant).
 */
void inpResetChannelDefaults(u8 channel, u8 key)
{
    u8* p;
    if (key != INP_INVALID_SLOT)
    {
        p = &gInpChannelDefaultsByKey[key][channel];
    }
    else
    {
        p = &gInpChannelDefaults[channel];
    }
    *p = 2;
}

void inpAddCtrl(int obj, int ctrl, int value, int flags, u32 flag)
{
    InpCtrlRing* ring = (InpCtrlRing*)obj;
    u8 counter;
    if ((flags & 0xff) == 0)
    {
        ring->count = 0;
    }
    if (ring->count < 4)
    {
        counter = ring->count++;
        if (flag == 0)
        {
            ctrl = inpTranslateExCtrl(ctrl);
        }
        else
        {
            flags |= 0x10;
        }
        ring->slots[counter].ctrl = ctrl;
        ring->slots[counter].flags = flags;
        ring->slots[counter].value = value;
    }
}

/*
 * Copy one FX controller value between two voice slots' global controller banks.
 */
void inpFXCopyCtrl(u8 controller, int dstState, int srcState)
{
    u32 ctrl;
    u32 dstVoice;
    u32 srcVoice;
    u8* stateBase;
    u8* bank;

    ctrl = controller & 0xff;
    stateBase = (u8*)lbl_803CD760;
    dstVoice = ((McmdVoiceState*)dstState)->voiceHandle & 0xff;
    srcVoice = ((McmdVoiceState*)srcState)->voiceHandle & 0xff;

    if (ctrl < 0x40)
    {
        ctrl = controller & 0x1f;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 0x20;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (controller == MCMD_CTRL_PITCH_BEND || controller == MCMD_CTRL_PITCH_BEND + 1)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (controller == MCMD_CTRL_DOPPLER || controller == MCMD_CTRL_DOPPLER + 1)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) = *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
}

/*
 * Set a byte in either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 */
void inpSetMidiLastNote(u8 channel, u8 key, u8 v)
{
    if (key != INP_INVALID_SLOT)
    {
        lbl_803CD760[key][channel] = v;
    }
    else
    {
        gInpMidiLastNote[channel] = v;
    }
}

/*
 * Get a byte from either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 */
u8 inpGetMidiLastNote(u8 channel, u8 key)
{
    if (key != INP_INVALID_SLOT)
    {
        return lbl_803CD760[key][channel];
    }
    return gInpMidiLastNote[channel];
}

u8 gInpMidiCtrlByKey[0x4300];
u8 gInpMidiCtrl[0x2180];
u8 gInpMidiLastNote[0x40];
u8 lbl_803CD760[8][INP_MIDI_SLOT_COUNT];
