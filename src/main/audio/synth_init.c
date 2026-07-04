#include "src/main/audio/synth_internal.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef signed char s8;

typedef struct LAYER
{
    u16 id;
    u8 keyLow;
    u8 keyHigh;
    s8 transpose;
    u8 volume;
    s16 prioOffset;
    u8 panning;
    u8 reserved[3];
} LAYER;

typedef struct LayerVoice
{
    u8 pad0[0xEC];
    u32 child;
    u32 parent;
    u8 padF4[0x11C - 0xF4];
    u8 block;
    u8 pad11D[0x404 - 0x11D];
} LayerVoice;

extern LayerVoice* synthVoice;

extern void* dataGetLayer(u16 cid, u16* n);
extern u16 inpGetMidiCtrl(u8 ctrl, u8 midi, u8 midiSet);
extern u32 audioFn_8026f630(u8 key, u8 midi, u8 midiSet, u32 newVID, u32* rejected);
extern u32 macStart(u16 macid, u8 priority, u8 maxVoices, u16 allocId, u8 key, u8 vol, u8 panning, u8 midi, u8 midiSet, u8 section, u16 step, u16 trackid, u8 new_vid, u8 vGroup, u8 studio, u32 itd);
extern u32 StartKeymap(u16 keymapID, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol,
                       u8 panning, u8 midi, u8 midiSet, u8 section, u16 step, u16 trackid,
                       u32 vidFlag, u8 vGroup, u8 studio, u32 itd);
extern u32 vidMakeRoot(LayerVoice* voice);

u32 audioLayerFn_8026f8b8(u16 layerID, s16 prio, u8 maxVoices, u16 allocId, u8 key, u8 vol,
                          u8 panning, u8 midi, u8 midiSet, u8 section, u16 step, u16 trackid,
                          u32 vidFlag, u8 vGroup, u8 studio, u32 itd)
{
    u16 n;
    u32 vid;
    u32 new_id;
    u32 id;
    LAYER* l;
    s32 p;
    s32 k;
    u8 v;
    u8 mKey;

    vid = 0xFFFFFFFF;
    if ((l = dataGetLayer(layerID, &n)) == NULL)
    {
        goto end;
    }

    mKey = key & 0x7f;
    for (; n != 0; --n, l++)
    {
        if (l->id == 0xffff || l->keyLow > mKey || l->keyHigh < mKey)
        {
            continue;
        }

        k = mKey + l->transpose;
        k = k > 127 ? 127 : k < 0 ? 0 : k;

        if ((l->id & 0xC000) == 0)
        {
            u32 rejected;
            u32 ok;
            if (inpGetMidiCtrl(MCMD_CTRL_PORTAMENTO, midi, midiSet) > 8064)
            {
                new_id = audioFn_8026f630(k & 0x7f, midi, midiSet, 0, &rejected);
                ok = !rejected;
            }
            else
            {
                new_id = 0xFFFFFFFF;
                ok = 1;
            }
            if (!ok)
            {
                continue;
            }
            if (new_id != 0xFFFFFFFF)
            {
                goto apply_new_id;
            }
        }

        if ((l->panning & 0x80) == 0)
        {
            p = l->panning - 0x40;
            p += panning;
            p = p < 0 ? 0 : p > 0x7f ? 0x7f : p;
        }
        else
        {
            p = 0x80;
        }

        v = (vol * l->volume) / 0x7f;
        prio += l->prioOffset;
        prio = prio > 0xff ? 0xff : prio < 0 ? 0 : prio;

        switch (l->id & 0xC000)
        {
        case 0:
            new_id = macStart(l->id, prio, maxVoices, allocId, k | (key & 0x80), v, p, midi,
                              midiSet, section, step, trackid, 0, vGroup, studio, itd);
            break;
        case 0x4000:
            new_id = StartKeymap(l->id, prio, maxVoices, allocId, k | (key & 0x80), v, p,
                                 midi, midiSet, section, step, trackid, 0, vGroup, studio,
                                 itd);
            break;
        case 0x8000:
            new_id = audioLayerFn_8026f8b8(l->id, prio, maxVoices, allocId, k | (key & 0x80), v, p,
                                           midi, midiSet, section, step, trackid, 0, vGroup, studio,
                                           itd);
            break;
        }

        if (new_id != 0xFFFFFFFF)
        {
        apply_new_id:
            if (vid == 0xFFFFFFFF)
            {
                if (vidFlag != 0)
                {
                    vid = vidMakeRoot(&synthVoice[new_id & 0xff]);
                }
                else
                {
                    vid = new_id;
                }
            }
            else
            {
                synthVoice[id & 0xff].child = new_id;
                synthVoice[new_id & 0xff].parent = id;
            }
            id = new_id;
            while (synthVoice[id & 0xff].child != 0xFFFFFFFF)
            {
                synthVoice[id & 0xff].block = 1;
                id = synthVoice[id & 0xff].child;
            }
            synthVoice[id & 0xff].block = 1;
        }
    }

end:
    return vid;
}
