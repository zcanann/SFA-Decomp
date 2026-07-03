#include "main/audio/snd3d_room.h"
#include "main/audio/synth_delay.h"
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
extern f32 lbl_803E78A0;
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
        0.0f, 3.05185e-05f, 0.000152593f, 0.000396741f, 0.000701926f, 0.00112918f,
        0.001648f, 0.00222785f, 0.00292978f, 0.00372326f, 0.00460829f, 0.00558489f,
        0.00665304f, 0.00784326f, 0.00912503f, 0.0104984f, 0.0119633f, 0.0135502f,
        0.0151982f, 0.0169988f, 0.0188604f, 0.0208441f, 0.0229194f, 0.0251167f,
        0.0274056f, 0.0298166f, 0.0323191f, 0.0349437f, 0.0376598f, 0.0404675f,
        0.0434278f, 0.0464797f, 0.0496231f, 0.0528886f, 0.0562761f, 0.0597858f,
        0.0633869f, 0.0671102f, 0.0709555f, 0.0749229f, 0.0789819f, 0.0831629f,
        0.087466f, 0.0919218f, 0.096469f, 0.101138f, 0.10593f, 0.110843f,
        0.115879f, 0.121036f, 0.126347f, 0.131748f, 0.137303f, 0.142979f,
        0.148778f, 0.154729f, 0.160772f, 0.166997f, 0.173315f, 0.179785f,
        0.186407f, 0.193121f, 0.200018f, 0.207007f, 0.214179f, 0.221473f,
        0.228919f, 0.236488f, 0.244209f, 0.252083f, 0.260079f, 0.268258f,
        0.276559f, 0.285012f, 0.293649f, 0.302408f, 0.311319f, 0.320383f,
        0.3296f, 0.339f, 0.348521f, 0.358226f, 0.368084f, 0.378094f,
        0.388287f, 0.398633f, 0.409131f, 0.419813f, 0.430647f, 0.441664f,
        0.452864f, 0.464217f, 0.475753f, 0.487442f, 0.499313f, 0.511399f,
        0.523606f, 0.536027f, 0.548631f, 0.561419f, 0.574389f, 0.587542f,
        0.600879f, 0.614399f, 0.628132f, 0.642018f, 0.656148f, 0.670431f,
        0.684927f, 0.699637f, 0.71453f, 0.729637f, 0.744926f, 0.76043f,
        0.776147f, 0.792077f, 0.808191f, 0.824549f, 0.84109f, 0.857845f,
        0.874844f, 0.892056f, 0.909452f, 0.927122f, 0.945006f, 0.963073f,
        0.981414f, 1.0f, 1.0f,
    },
    { 0.0f, 0.7079f, 1.0f, 1.0f },
    { 0.575f, 0.7079f, 1.0f, 1.0f },
    0.0f
};
extern f32 voiceAdsrSustainTable[129];
extern f32 gSnd3dRoomVolIndexScale;
extern f32 lbl_803E785C;
extern f32 lbl_803E7860;
extern f32 gSnd3dRoomPanFixedToFloat;
extern f32 lbl_803E7874;
extern f32 lbl_803E7878;
extern f32 lbl_803E787C;

#pragma fp_contract off
#define SAL_FMOD1(dst, x) \
    if (__fabs(lbl_803E785C) > __fabs(x)) { \
        dst = (x); \
    } else { \
        dst = (x) - lbl_803E785C * (f32)(s64)(u64)((x) / lbl_803E785C); \
    }

/*
 * salCalcVolumeMatrix
 * EN v1.0 Address: 0x8027F2AC
 * EN v1.0 Size: 1944b
 */
void salCalcVolumeMatrix(u8 voltab_index, f32* out, u32 pan, u32 span, u32 itd, u32 dpl2,
                         f32 vol, f32 auxa, f32 auxb)
{
    SalVolTab* tabs;
    f32* vol_tab;
    f32 p, sp, t;
    u32 pan_i, pan_im, span_i, span_im;
    u32 rpan_i, rpan_im;
    u32 pan2, span2;
    u32 i;
    f32 om_span_f, om_span_fm, om_pan_f, om_pan_fm;
    f32 rpan_fm, rpan_f;
    f32 span_fm, pan_fm, span_f, pan_f;
    f32 v, f, vs, ftmp, one_;
    f32* pan1;

    tabs = &gSnd3dRoomVolTable;
    if (voltab_index == 0)
    {
        vol_tab = tabs->vol;
    }
    else
    {
        vol_tab = voiceAdsrSustainTable;
    }

    if (pan == 0x800000)
    {
        pan = 0;
        span = 0x7f0000;
    }

    if (pan <= 0x10000)
    {
        pan2 = 0;
    }
    else
    {
        pan2 = pan - 0x10000;
    }
    if (span <= 0x10000)
    {
        span2 = 0;
    }
    else
    {
        span2 = span - 0x10000;
    }

    p = gSnd3dRoomPanFixedToFloat * pan2;
    sp = gSnd3dRoomPanFixedToFloat * span2;

    if (dpl2 != 0)
    {
        SAL_FMOD1(rpan_f, p);
        rpan_i = p;
        t = lbl_803E7874 - p;
        SAL_FMOD1(rpan_fm, t);
        rpan_im = t;
    }

    if (itd != 0)
    {
        p = lbl_803E785C + lbl_803E7878 * (p - lbl_803E785C);
    }

    SAL_FMOD1(pan_f, p);
    pan_i = p;
    SAL_FMOD1(span_f, sp);
    span_i = sp;
    p = lbl_803E7874 - p;
    sp = lbl_803E7874 - sp;
    SAL_FMOD1(pan_fm, p);
    pan_im = p;
    SAL_FMOD1(span_fm, sp);
    span_im = sp;

    if (dpl2 == 0)
    {
        ftmp = gSnd3dRoomVolIndexScale * vol;
        i = ftmp;
        one_ = lbl_803E785C;
        pan1 = tabs->pan + 1;
        om_span_f = one_ - span_f;
        v = ftmp - i;
        om_span_fm = one_ - span_fm;
        f = (one_ - v) * vol_tab[i] + v * vol_tab[i + 1];
        om_pan_f = one_ - pan_f;
        om_pan_fm = one_ - pan_fm;
        out[2] = lbl_803E7860 * (f * (om_span_f * tabs->pan[span_i] + span_f * pan1[span_i]));
        f = f * (om_span_fm * tabs->pan[span_im] + span_fm * pan1[span_im]);
        out[1] = f * (om_pan_f * tabs->pan[pan_i] + pan_f * pan1[pan_i]);
        out[0] = f * (om_pan_fm * tabs->pan[pan_im] + pan_fm * pan1[pan_im]);

        ftmp = gSnd3dRoomVolIndexScale * auxa;
        i = ftmp;
        v = ftmp - i;
        v = (lbl_803E785C - v) * vol_tab[i] + v * vol_tab[i + 1];
        out[5] = lbl_803E7860 * (v * (om_span_f * tabs->pan[span_i] + span_f * pan1[span_i]));
        v = v * (om_span_fm * tabs->pan[span_im] + span_fm * pan1[span_im]);
        out[4] = v * (om_pan_f * tabs->pan[pan_i] + pan_f * pan1[pan_i]);
        out[3] = v * (om_pan_fm * tabs->pan[pan_im] + pan_fm * pan1[pan_im]);

        ftmp = gSnd3dRoomVolIndexScale * auxb;
        i = ftmp;
        v = ftmp - i;
        v = (lbl_803E785C - v) * vol_tab[i] + v * vol_tab[i + 1];
        out[8] = lbl_803E7860 * (v * (om_span_f * tabs->pan[span_i] + span_f * pan1[span_i]));
        v = v * (om_span_fm * tabs->pan[span_im] + span_fm * pan1[span_im]);
        out[7] = v * (om_pan_f * tabs->pan[pan_i] + pan_f * pan1[pan_i]);
        out[6] = v * (om_pan_fm * tabs->pan[pan_im] + pan_fm * pan1[pan_im]);
    }
    else
    {
        ftmp = gSnd3dRoomVolIndexScale * vol;
        i = ftmp;
        one_ = lbl_803E785C;
        pan1 = tabs->pan + 1;
        om_span_f = one_ - span_f;
        om_span_fm = one_ - span_fm;
        v = ftmp - i;
        om_pan_f = one_ - pan_f;
        f = (one_ - v) * vol_tab[i] + v * vol_tab[i + 1];
        om_pan_fm = one_ - pan_fm;
        vs = f * (om_span_f * tabs->pan[span_i] + span_f * pan1[span_i]);
        f = f * (om_span_fm * tabs->pan[span_im] + span_fm * pan1[span_im]);
        out[1] = f * (om_pan_f * tabs->pan[pan_i] + pan_f * pan1[pan_i]);
        out[0] = f * (om_pan_fm * tabs->pan[pan_im] + pan_fm * pan1[pan_im]);
        out[7] = vs * ((one_ - rpan_f) * tabs->pan_dpl2[rpan_i] + rpan_f * pan1[rpan_i]);
        out[6] = vs * ((one_ - rpan_fm) * tabs->pan_dpl2[rpan_im] + rpan_fm * pan1[rpan_im]);

        ftmp = gSnd3dRoomVolIndexScale * auxa;
        i = ftmp;
        v = ftmp - i;
        v = (lbl_803E785C - v) * vol_tab[i] + v * vol_tab[i + 1];
        out[5] = lbl_803E7860 * (v * (om_span_f * tabs->pan[span_i] + span_f * pan1[span_i]));
        v = v * (om_span_fm * tabs->pan[span_im] + span_fm * pan1[span_im]);
        out[4] = v * (om_pan_f * tabs->pan[pan_i] + pan_f * pan1[pan_i]);
        out[3] = v * (om_pan_fm * tabs->pan[pan_im] + pan_fm * pan1[pan_im]);

        out[2] = lbl_803E787C;
        out[8] = lbl_803E787C;
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
                        if (scanEntry->assignedVoice != 0xff &&
                            worstDistance < scanEntry->averageDistanceSq)
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
                if ((entry->flags & 0x80000000) != 0)
                {
                    entry->fade += 0x40000;
                    if (entry->fade >= 0x7f0000)
                    {
                        entry->fade = 0x7f0000;
                        entry->flags &= 0x7fffffff;
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
                if ((entry->flags & 0x40000000) != 0)
                {
                    entry->fade -= 0x40000;
                    if ((s32)entry->fade >= 0)
                    {
                        entry->fade = 0;
                        entry->flags &= 0xbfffffff;
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
    f32 scale;
    s32 v0, v1;

    scale = lbl_803E78A0;
    for (link = s3dDoorRoot; link != NULL; link = link->next)
    {
        if ((link->flags & 0x80000000) == 0)
        {
            if (link->source->assignedVoice != 0xff)
            {
                if (link->target->assignedVoice != 0xff)
                {
                    v0 = (s32)(scale * link->inputScale);
                    v1 = (s32)((f32)link->sendLevel * link->inputScale);
                    link->studioInput[1] = v1;
                    link->studioInput[2] = 0;
                    link->studioInput[0] = v0;
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
                    (link->target->assignedVoice != 0xff &&
                        link->target->assignedVoice == link->activeInput))
                {
                    synthRemoveStudioInput(link->activeInput, link->studioInput);
                }
                link->flags &= 0x7fffffff;
            }
            else
            {
                v0 = (s32)(scale * link->inputScale);
                v1 = (s32)((f32)link->sendLevel * link->inputScale);
                link->studioInput[1] = v1;
                link->studioInput[2] = 0;
                link->studioInput[0] = v0;
            }
        }
    }
}
#pragma fp_contract reset
