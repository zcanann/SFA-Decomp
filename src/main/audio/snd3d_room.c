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

extern SalVolTab gSnd3dRoomVolTable;
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
    f32 fadeScale;
    f64 fadeThreshold;

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
                f32 distanceSq;
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
                    if (!listenerOwned && worstDistance <= distanceSq)
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
                if (listenerOwned)
                {
                    entry->fade = 0x7f0000;
                }
                else
                {
                    entry->fade = 0;
                }
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
