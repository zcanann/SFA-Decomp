#include "main/audio/snd3d_room.h"
#include "main/audio/snd_synth_api.h"

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
extern u32 synthSendKeyOff(u32 handle);

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
                distanceSq = 0.0f;
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
    Snd3DEmitter* voice;
    SndSpatialEntry* scanEntry;
    SndSpatialEntry* evictedEntry;
    SndSpatialEntry* entry;
    struct
    {
        f32 x, y, z;
    } d;
    f32 distanceSq;
    f32 worstDistance;
    u32 listenerCount;
    u32 i;
    u32 mask;
    u8 listenerOwned;

    s3dUpdateRoomDistances();

    listenerCount = 0;
    for (listener = s3dListenerRoot; listener != NULL; listener = listener->next)
    {
        listenerCount++;
    }

    if (listenerCount != 0)
    {
        for (entry = s3dRoomRoot; entry != NULL; entry = entry->next)
        {
            if (entry->assignedVoice == 0xff)
            {
                distanceSq = 0.0f;
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

                mask = ~(-1 << snd_max_studios);
                if (mask != (snd_used_studios & mask))
                {
                    for (i = 0; i < snd_max_studios; i++)
                    {
                        if ((snd_used_studios & (1 << i)) == 0)
                        {
                            break;
                        }
                    }
                    snd_used_studios |= 1 << i;
                    entry->assignedVoice = i + snd_base_studio;
                }
                else
                {
                    worstDistance = -1.0f;

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
                if ((f32)(1.2014794e-07f * entry->fade) >= 0.5)
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
                    if ((f32)(1.2014794e-07f * entry->fade) >= 0.5)
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
                    if ((f32)(1.2014794e-07f * entry->fade) >= 0.5)
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
