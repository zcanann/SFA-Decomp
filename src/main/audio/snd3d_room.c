#include "main/audio/snd3d_room.h"
#include "main/audio/synth_delay.h"

/* SndSpatialEntry.flags: room-fade one-shots driven per update tick */
#define S3D_ENTRY_FADE_IN  0x80000000 /* ramp fade up toward full, then clear */
#define S3D_ENTRY_FADE_OUT 0x40000000 /* ramp fade down toward zero, then clear */

#pragma exceptions on

extern Snd3DEmitter* s3dEmitterRoot;
extern SndSpatialListener* s3dListenerRoot;
extern SndSpatialEntry* s3dRoomRoot;
extern SndStudioInputLink* s3dDoorRoot;
extern u32 snd_used_studios;
extern u8 snd_base_studio;
extern u8 snd_max_studios;
extern f32 lbl_803E7880;
extern f32 lbl_803E7890;
extern f32 gSnd3dRoomFadeFixedToFloat;
extern f64 lbl_803E7898;
extern void synthActivateStudio(u8 studio, int active, int unk);
extern void synthDeactivateStudio(u8 studio);
extern void synthAddStudioInput(u8 studio, u8* input);
extern void synthRemoveStudioInput(u8 studio, u8* input);

typedef struct
{
    f32 vol[129];
    f32 pan[4];
    f32 pan_dpl2[4];
    f32 end;
} SalVolTab;

SalVolTab gSnd3dRoomVolTable = {
    {
        0.0f,        3.05185e-05f, 0.000152593f, 0.000396741f, 0.000701926f, 0.00112918f, 0.001648f,   0.00222785f,
        0.00292978f, 0.00372326f,  0.00460829f,  0.00558489f,  0.00665304f,  0.00784326f, 0.00912503f, 0.0104984f,
        0.0119633f,  0.0135502f,   0.0151982f,   0.0169988f,   0.0188604f,   0.0208441f,  0.0229194f,  0.0251167f,
        0.0274056f,  0.0298166f,   0.0323191f,   0.0349437f,   0.0376598f,   0.0404675f,  0.0434278f,  0.0464797f,
        0.0496231f,  0.0528886f,   0.0562761f,   0.0597858f,   0.0633869f,   0.0671102f,  0.0709555f,  0.0749229f,
        0.0789819f,  0.0831629f,   0.087466f,    0.0919218f,   0.096469f,    0.101138f,   0.10593f,    0.110843f,
        0.115879f,   0.121036f,    0.126347f,    0.131748f,    0.137303f,    0.142979f,   0.148778f,   0.154729f,
        0.160772f,   0.166997f,    0.173315f,    0.179785f,    0.186407f,    0.193121f,   0.200018f,   0.207007f,
        0.214179f,   0.221473f,    0.228919f,    0.236488f,    0.244209f,    0.252083f,   0.260079f,   0.268258f,
        0.276559f,   0.285012f,    0.293649f,    0.302408f,    0.311319f,    0.320383f,   0.3296f,     0.339f,
        0.348521f,   0.358226f,    0.368084f,    0.378094f,    0.388287f,    0.398633f,   0.409131f,   0.419813f,
        0.430647f,   0.441664f,    0.452864f,    0.464217f,    0.475753f,    0.487442f,   0.499313f,   0.511399f,
        0.523606f,   0.536027f,    0.548631f,    0.561419f,    0.574389f,    0.587542f,   0.600879f,   0.614399f,
        0.628132f,   0.642018f,    0.656148f,    0.670431f,    0.684927f,    0.699637f,   0.71453f,    0.729637f,
        0.744926f,   0.76043f,     0.776147f,    0.792077f,    0.808191f,    0.824549f,   0.84109f,    0.857845f,
        0.874844f,   0.892056f,    0.909452f,    0.927122f,    0.945006f,    0.963073f,   0.981414f,   1.0f,
        1.0f,
    },
    {0.0f, 0.7079f, 1.0f, 1.0f},
    {0.575f, 0.7079f, 1.0f, 1.0f},
    0.0f};
extern f32 voiceAdsrSustainTable[129];

#pragma fp_contract off
static inline f32 sal_fmod(f32 x, f32 y)
{
    s64 n;
    f32 ay;
    f32 ax;

    ay = __fabsf(y);
    ax = __fabsf(x);
    if (ay > ax)
    {
        return x;
    }
    n = (s64)(u64)(x / y);
    return x - y * (f32)n;
}

typedef struct SAL_PANINFO
{
    u32 pan_i;
    u32 pan_im;
    u32 span_i;
    u32 span_im;
    u32 rpan_i;
    u32 rpan_im;
    f32 pan_f;
    f32 pan_fm;
    f32 span_f;
    f32 span_fm;
    f32 rpan_f;
    f32 rpan_fm;
} SAL_PANINFO;

/* The +1 pan lookups read the global directly so &pan[1] stays one shared address constant. */
static inline void CalcBus(f32* vol_tab, f32* v_out, f32 vol, SAL_PANINFO* pi, SalVolTab* tabs)
{
    u32 i;
    f32 level;
    f32 frac;

    i = 127.0f * vol;
    frac = (127.0f * vol) - (f32)i;
    level = (1.0f - frac) * vol_tab[i] + frac * vol_tab[i + 1];
    v_out[2] =
        0.7079f *
        (level * ((1.0f - pi->span_f) * tabs->pan[pi->span_i] + pi->span_f * gSnd3dRoomVolTable.pan[pi->span_i + 1]));
    level =
        level * ((1.0f - pi->span_fm) * tabs->pan[pi->span_im] + pi->span_fm * gSnd3dRoomVolTable.pan[pi->span_im + 1]);
    v_out[1] = level * ((1.0f - pi->pan_f) * tabs->pan[pi->pan_i] + pi->pan_f * gSnd3dRoomVolTable.pan[pi->pan_i + 1]);
    v_out[0] =
        level * ((1.0f - pi->pan_fm) * tabs->pan[pi->pan_im] + pi->pan_fm * gSnd3dRoomVolTable.pan[pi->pan_im + 1]);
}

static inline void CalcBusDPL2(f32* vol_tab, f32* v_out, f32 vol, SAL_PANINFO* pi, SalVolTab* tabs)
{
    u32 i;
    f32 frac;
    f32 level;
    f32 surround;

    i = 127.0f * vol;
    frac = (127.0f * vol) - (f32)i;
    level = (1.0f - frac) * vol_tab[i] + frac * vol_tab[i + 1];
    surround =
        level * ((1.0f - pi->span_f) * tabs->pan[pi->span_i] + pi->span_f * gSnd3dRoomVolTable.pan[pi->span_i + 1]);
    level =
        level * ((1.0f - pi->span_fm) * tabs->pan[pi->span_im] + pi->span_fm * gSnd3dRoomVolTable.pan[pi->span_im + 1]);
    v_out[1] = level * ((1.0f - pi->pan_f) * tabs->pan[pi->pan_i] + pi->pan_f * gSnd3dRoomVolTable.pan[pi->pan_i + 1]);
    v_out[0] =
        level * ((1.0f - pi->pan_fm) * tabs->pan[pi->pan_im] + pi->pan_fm * gSnd3dRoomVolTable.pan[pi->pan_im + 1]);
    v_out[7] = surround *
               ((1.0f - pi->rpan_f) * tabs->pan_dpl2[pi->rpan_i] + pi->rpan_f * gSnd3dRoomVolTable.pan[pi->rpan_i + 1]);
    v_out[6] = surround * ((1.0f - pi->rpan_fm) * tabs->pan_dpl2[pi->rpan_im] +
                           pi->rpan_fm * gSnd3dRoomVolTable.pan[pi->rpan_im + 1]);
}

void salCalcVolumeMatrix(u8 voltab_index, f32* out, u32 pan, u32 span, u32 itd, u32 dpl2, f32 vol, f32 auxa, f32 auxb)
{
    SalVolTab* tabs;
    f32* vol_tab;
    f32 panPos, spanPos, rearPan;
    u32 panAdj, spanAdj;
    SAL_PANINFO pi;

    tabs = &gSnd3dRoomVolTable;
    vol_tab = (voltab_index == 0) ? tabs->vol : voiceAdsrSustainTable;

    if (pan == 0x800000)
    {
        pan = 0;
        span = 0x7f0000;
    }

    if (pan <= 0x10000)
    {
        panAdj = 0;
    }
    else
    {
        panAdj = pan - 0x10000;
    }
    if (span <= 0x10000)
    {
        spanAdj = 0;
    }
    else
    {
        spanAdj = span - 0x10000;
    }

    panPos = 2.4220301e-07f * panAdj;
    spanPos = 2.4220301e-07f * spanAdj;

    if (dpl2 != 0)
    {
        pi.rpan_f = sal_fmod(panPos, 1.0f);
        pi.rpan_i = panPos;
        rearPan = 2.0f - panPos;
        pi.rpan_fm = sal_fmod(rearPan, 1.0f);
        pi.rpan_im = rearPan;
    }

    if (itd != 0)
    {
        panPos = 1.0f + 0.76604f * (panPos - 1.0f);
    }

    pi.pan_f = sal_fmod(panPos, 1.0f);
    pi.pan_i = panPos;
    pi.span_f = sal_fmod(spanPos, 1.0f);
    pi.span_i = spanPos;
    panPos = 2.0f - panPos;
    spanPos = 2.0f - spanPos;
    pi.pan_fm = sal_fmod(panPos, 1.0f);
    pi.pan_im = panPos;
    pi.span_fm = sal_fmod(spanPos, 1.0f);
    pi.span_im = spanPos;

    if (dpl2 == 0)
    {
        CalcBus(vol_tab, out, vol, &pi, tabs);
        CalcBus(vol_tab, out + 3, auxa, &pi, tabs);
        CalcBus(vol_tab, out + 6, auxb, &pi, tabs);
    }
    else
    {
        CalcBusDPL2(vol_tab, out, vol, &pi, tabs);
        CalcBus(vol_tab, out + 3, auxa, &pi, tabs);
        out[2] = 0.0f;
        out[8] = 0.0f;
    }
}
#pragma fp_contract reset

/*
 * Update average squared distance from each active spatial entry to all
 * registered listeners.
 */
#pragma fp_contract off
void s3dUpdateRoomDistances(void)
{
    SndSpatialListener* listener;
    SndSpatialEntry* entry;
    u32 listenerCount;

    listenerCount = 0;
    for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
    {
        listenerCount++;
    }

    if (listenerCount != 0)
    {
        for (entry = s3dRoomRoot; entry != NULL; entry = entry->next)
        {
            f32 distanceSq;
            struct
            {
                f32 x, y, z;
            } d;

            if (entry->assignedVoice != 0xff)
            {
                distanceSq = lbl_803E7880;
                for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
                {
                    d.x = entry->posX - listener->posX;
                    d.y = entry->posY - listener->posY;
                    d.z = entry->posZ - listener->posZ;

                    distanceSq += d.z * d.z + (d.x * d.x + d.y * d.y);
                }
                entry->averageDistanceSq = distanceSq / listenerCount;
            }
        }
    }
}

/*
 * Allocate scarce studio voices to spatial entries and update their
 * activation fade state.
 */
void s3dAllocateRoomStudios(void)
{
    SndSpatialListener* listener;
    u32 listenerCount;
    SndSpatialEntry* entry;
    f32 distanceSq;
    f64 fadeThreshold;
    f32 fadeScale;

    s3dUpdateRoomDistances();

    listenerCount = 0;
    for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
    {
        listenerCount++;
    }

    if (listenerCount != 0)
    {
        fadeScale = gSnd3dRoomFadeFixedToFloat;
        fadeThreshold = lbl_803E7898;
        for (entry = s3dRoomRoot; entry != NULL; entry = entry->next)
        {
            if (entry->assignedVoice == 0xff)
            {
                SndSpatialEntry* evictedEntry;
                u32 studioCount;
                u8 listenerOwned;
                struct
                {
                    f32 x, y, z;
                } d;

                distanceSq = lbl_803E7880;
                for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
                {
                    d.x = entry->posX - listener->posX;
                    d.y = entry->posY - listener->posY;
                    d.z = entry->posZ - listener->posZ;

                    distanceSq += d.z * d.z + (d.x * d.x + d.y * d.y);
                }
                listenerOwned = false;
                distanceSq = distanceSq / listenerCount;
                for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
                {
                    if (listener->entry == entry)
                    {
                        listenerOwned = true;
                        break;
                    }
                }

                studioCount = snd_max_studios;
                if (~(-1 << studioCount) != (~(-1 << studioCount) & snd_used_studios))
                {
                    int i;

                    for (i = 0; i < studioCount; i++)
                    {
                        if ((snd_used_studios & (1 << i)) == 0)
                        {
                            break;
                        }
                    }
                    snd_used_studios |= 1 << i;
                    entry->assignedVoice = (u8)(i + snd_base_studio);
                }
                else
                {
                    f32 worstDistance = lbl_803E7890;
                    Snd3DEmitter* voice;
                    SndSpatialEntry* scanEntry;

                    for (scanEntry = s3dRoomRoot; scanEntry != NULL; scanEntry = scanEntry->next)
                    {
                        if (scanEntry->assignedVoice != 0xff && worstDistance < scanEntry->averageDistanceSq)
                        {
                            worstDistance = scanEntry->averageDistanceSq;
                            evictedEntry = scanEntry;
                        }
                    }
                    if (!listenerOwned && !(worstDistance > distanceSq))
                    {
                        continue;
                    }
                    for (voice = s3dEmitterRoot; voice != NULL; voice = voice->next)
                    {
                        if (voice->entry == evictedEntry)
                        {
                            synthSendKeyOff(voice->handle);
                            voice->flags |= S3D_EMITTER_FLAG_WAITING_FOR_ROOM;
                            voice->handle = 0xffffffff;
                        }
                    }
                    if (evictedEntry->evictCallback != NULL)
                    {
                        evictedEntry->evictCallback(evictedEntry->assignedVoice);
                    }
                    synthDeactivateStudio(evictedEntry->assignedVoice);
                    entry->assignedVoice = evictedEntry->assignedVoice;
                    evictedEntry->assignedVoice = 0xff;
                    evictedEntry->flags = 0;
                }

                entry->averageDistanceSq = distanceSq;
                entry->fade = listenerOwned ? 0x7f0000 : 0;
                if ((f32)(fadeScale * entry->fade) >= fadeThreshold)
                {
                    synthActivateStudio(entry->assignedVoice, 1, 0);
                }
                else
                {
                    synthActivateStudio(entry->assignedVoice, 0, 0);
                }
                if (entry->activateCallback != NULL)
                {
                    entry->activateCallback(entry->assignedVoice, entry->callbackUser);
                }
            }
            else
            {
                if ((entry->flags & S3D_ENTRY_FADE_IN) != 0)
                {
                    entry->fade += 0x40000;
                    if (entry->fade >= 0x7f0000)
                    {
                        entry->fade = 0x7f0000;
                        entry->flags &= ~S3D_ENTRY_FADE_IN;
                    }
                    if ((f32)(fadeScale * entry->fade) >= fadeThreshold)
                    {
                        synthActivateStudio(entry->assignedVoice, 1, 0);
                    }
                    else
                    {
                        synthActivateStudio(entry->assignedVoice, 0, 0);
                    }
                }
                if ((entry->flags & S3D_ENTRY_FADE_OUT) != 0)
                {
                    entry->fade -= 0x40000;
                    if ((s32)entry->fade >= 0)
                    {
                        entry->fade = 0;
                        entry->flags &= ~S3D_ENTRY_FADE_OUT;
                    }
                    if ((f32)(fadeScale * entry->fade) >= fadeThreshold)
                    {
                        synthActivateStudio(entry->assignedVoice, 1, 0);
                    }
                    else
                    {
                        synthActivateStudio(entry->assignedVoice, 0, 0);
                    }
                }
            }
        }
    }
}

/*
 * Update studio-input bridges between spatial entries as voices appear
 * and disappear.
 */
void s3dUpdateDoorStudioInputs(void)
{
    SndStudioInputLink* link;
    f32 f;
    f32 v;

    for (link = s3dDoorRoot; link != NULL; link = link->next)
    {
        if ((link->flags & 0x80000000) == 0)
        {
            if (link->source->assignedVoice != 0xff)
            {
                if (link->target->assignedVoice != 0xff)
                {
                    v = link->inputScale;
                    f = (1.0f - v) * v;
                    link->studioInput[1] = (s32)((f32)link->sendLevel * v);
                    link->studioInput[2] = 0;
                    link->studioInput[0] = (s32)(127.0f * v);
                    if ((link->flags & 1) != 0)
                    {
                        link->studioInput[3] = link->target->assignedVoice;
                        synthAddStudioInput(link->source->assignedVoice, link->studioInput);
                    }
                    else
                    {
                        link->studioInput[3] = link->source->assignedVoice;
                        synthAddStudioInput(link->target->assignedVoice, link->studioInput);
                    }
                    link->flags |= 0x80000000;
                }
            }
        }
        else
        {
            u8 sourceVoice = link->source->assignedVoice;

            if (sourceVoice == 0xff || link->target->assignedVoice == 0xff)
            {
                if ((sourceVoice != 0xff && sourceVoice == link->activeInput) ||
                    (link->target->assignedVoice != 0xff && link->target->assignedVoice == link->activeInput))
                {
                    synthRemoveStudioInput(link->activeInput, link->studioInput);
                }
                link->flags &= 0x7fffffff;
            }
            else
            {
                v = link->inputScale;
                f = (1.0f - v) * v;
                link->studioInput[1] = (s32)((f32)link->sendLevel * v);
                link->studioInput[2] = 0;
                link->studioInput[0] = (s32)(127.0f * v);
            }
        }
    }
}
#pragma fp_contract reset
