#include "main/audio/inp_midi.h"
#include "main/audio/mcmd.h"
#include "string.h"

#pragma exceptions on
extern int inpTranslateExCtrl(int input);
extern u8 sInpMidiCtrlFullResetPreset[];
extern u8 sInpMidiCtrlMaskedResetPreset[];
extern u8 lbl_803CD760[][INP_MIDI_SLOT_COUNT];

typedef struct InpMidiState
{
    u8 pad0[0xC0];
    u8 midiCtrl[8][16][134]; /* 0x00C0 */
    u8 fxCtrl[16][134]; /* 0x43C0 */
} InpMidiState;
extern u8 gInpMidiLastNote[];
extern u8 gInpMidiCtrlByKey[];
extern u8 gInpMidiCtrl[];
extern u8 gInpChannelDefaultsByKey[][INP_MIDI_SLOT_COUNT];
extern u8 gInpChannelDefaults[];

/*
 * Reset a MIDI-controller/default table from one of two preset banks,
 * then mark the last-note/controller slot dirty via inpSetMidiLastNote.
 *
 * EN v1.1 Address: 0x80281A30, size 244b
 */
void inpResetMidiCtrl(u8 a, u8 b, u32 mode)
{
    u8* dst;
    u8* src;

    src = (mode != 0) ? sInpMidiCtrlFullResetPreset : sInpMidiCtrlMaskedResetPreset;

    if (b != INP_INVALID_SLOT)
    {
        dst = gInpMidiCtrlByKey + b * INP_MIDI_KEY_STRIDE + a * INP_MIDI_CTRL_BANK_SIZE;
    }
    else
    {
        dst = gInpMidiCtrl + a * INP_MIDI_CTRL_BANK_SIZE;
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

    inpSetMidiLastNote(a, b, 0xff);
}

/*
 * Read a 14-bit MIDI controller value from either the global channel defaults
 * or the per-key controller bank.
 */
u32 inpGetMidiCtrl(u8 controller, u32 slot, u32 key)
{
    u32 s;
    u32 k;
    u32 ctrl;
    InpMidiState* st;

    st = (InpMidiState*)lbl_803CD760;
    s = slot & 0xff;
    if (s != INP_INVALID_SLOT)
    {
        k = key & 0xff;
        if (k != INP_INVALID_SLOT)
        {
            ctrl = controller & 0xff;
            if (ctrl < 0x40)
            {
                return (u16)(((u32)st->midiCtrl[k][s][ctrl & 0x1f] << 7) |
                    st->midiCtrl[k][s][(ctrl & 0x1f) + 0x20]);
            }
            if (ctrl < 0x46)
            {
                return (u16)((st->midiCtrl[k][s][ctrl] < 0x40) ? 0 : 0x3fff);
            }
            if (ctrl >= 0x60 && ctrl < 0x66)
            {
                return 0;
            }
            if (((controller - 0x80) & 0xff) <= 1U)
            {
                return (u16)(((u32)st->midiCtrl[(u8)key][(u8)slot][controller & 0xfe] << 7) |
                    st->midiCtrl[(u8)key][(u8)slot][(controller & 0xfe) + 1]);
            }
            if (((controller - 0x84) & 0xff) <= 1U)
            {
                return (u16)(((u32)st->midiCtrl[(u8)key][(u8)slot][controller & 0xfe] << 7) |
                    st->midiCtrl[(u8)key][(u8)slot][(controller & 0xfe) + 1]);
            }
            return (u16)((u32)st->midiCtrl[(u8)key][(u8)slot][controller & 0xff] << 7);
        }

        ctrl = controller & 0xff;
        if (ctrl < 0x40)
        {
            return (u16)(((u32)st->fxCtrl[s][ctrl & 0x1f] << 7) |
                st->fxCtrl[s][(ctrl & 0x1f) + 0x20]);
        }
        if (ctrl < 0x46)
        {
            return (u16)((st->fxCtrl[s][ctrl] < 0x40) ? 0 : 0x3fff);
        }
        if (ctrl >= 0x60 && ctrl < 0x66)
        {
            return 0;
        }
        if (((controller - 0x80) & 0xff) <= 1U)
        {
            return (u16)(((u32)st->fxCtrl[(u8)slot][controller & 0xfe] << 7) |
                st->fxCtrl[(u8)slot][(controller & 0xfe) + 1]);
        }
        if (((controller - 0x84) & 0xff) <= 1U)
        {
            return (u16)(((u32)st->fxCtrl[(u8)slot][controller & 0xfe] << 7) |
                st->fxCtrl[(u8)slot][(controller & 0xfe) + 1]);
        }
        return (u16)((u32)st->fxCtrl[(u8)slot][controller & 0xff] << 7);
    }
    return 0;
}

/*
 * Returns pointer into either 1D or 2D voice-state table.
 *
 * EN v1.1 Address: 0x80281DB0, size 60b
 */
u8* inpGetChannelDefaults(u8 a, u8 b)
{
    if (b == INP_INVALID_SLOT)
    {
        return &gInpChannelDefaults[a];
    }
    return &gInpChannelDefaultsByKey[b][a];
}

/*
 * Stores 2 into voice-state slot (1D or 2D variant).
 *
 * EN v1.1 Address: 0x80281DEC, size 68b
 */
void inpResetChannelDefaults(u8 a, u8 b)
{
    u8* p;
    if (b != INP_INVALID_SLOT)
    {
        p = &gInpChannelDefaultsByKey[b][a];
    }
    else
    {
        p = &gInpChannelDefaults[a];
    }
    *p = 2;
}

/*
 * Push an event onto a 4-slot ring at obj+0x22. Resets counter when
 * the input flag (d) is zero. Slot layout: [b, d|0x10 or transformed
 * b, _, _, c, _, _, _].
 *
 * EN v1.1 Address: 0x80281E30, size 156b
 */
typedef struct InpCtrlRing
{
    struct
    {
        u8 ctrl; /* 0x0 */
        u8 flags; /* 0x1 */
        u8 pad[2];
        int value; /* 0x4 */
    } slots[4]; /* 0x00 */
    u8 pad20[2]; /* 0x20 */
    u8 count; /* 0x22 */
} InpCtrlRing;

void inpAddCtrl(int obj, int b, int c, int d, u32 flag)
{
    InpCtrlRing* ring = (InpCtrlRing*)obj;
    u8 counter;
    if ((d & 0xff) == 0)
    {
        ring->count = 0;
    }
    if (ring->count < 4)
    {
        counter = ring->count++;
        if (flag == 0)
        {
            b = inpTranslateExCtrl(b);
        }
        else
        {
            d |= 0x10;
        }
        ring->slots[counter].ctrl = b;
        ring->slots[counter].flags = d;
        ring->slots[counter].value = c;
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
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 0x20;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (((controller - 0x80) & 0xff) <= 1U)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    if (((controller - 0x84) & 0xff) <= 1U)
    {
        ctrl = controller & 0xfe;
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
                srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        bank = stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET + 1;
        *(bank + dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
            *(bank + srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
        return;
    }
    *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
            dstVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl) =
        *(stateBase + INP_MIDI_CTRL_GLOBAL_OFFSET +
            srcVoice * INP_MIDI_CTRL_BANK_SIZE + ctrl);
}

/*
 * Set a byte in either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x80281FE8, size 68b
 */
void inpSetMidiLastNote(u8 a, u8 b, u8 v)
{
    if (b != INP_INVALID_SLOT)
    {
        lbl_803CD760[b][a] = v;
    }
    else
    {
        gInpMidiLastNote[a] = v;
    }
}

/*
 * Get a byte from either gInpMidiLastNote[a] (1D, when b == 0xff) or
 * lbl_803CD760[b][a] (2D).
 *
 * EN v1.1 Address: 0x8028202C, size 68b
 */
u8 inpGetMidiLastNote(u8 a, u8 b)
{
    if (b != INP_INVALID_SLOT)
    {
        return lbl_803CD760[b][a];
    }
    return gInpMidiLastNote[a];
}

u8 gInpMidiCtrlByKey[0x4300];
u8 gInpMidiCtrl[0x2180];
