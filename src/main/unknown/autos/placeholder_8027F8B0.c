#include "ghidra_import.h"

typedef struct SndSpatialListener {
    struct SndSpatialListener *next;
    u8 pad04[4];
    struct SndSpatialEntry *entry;
    u8 pad0c[4];
    f32 x;
    f32 y;
    f32 z;
} SndSpatialListener;

typedef struct SndSpatialEntry {
    struct SndSpatialEntry *next;
    u8 pad04[4];
    u32 flags;
    f32 x;
    f32 y;
    f32 z;
    f32 averageDistanceSq;
    s8 assignedVoice;
    u8 pad1d[3];
    void (*activateCallback)(u8 voice, u32 user);
    void (*evictCallback)(u8 voice);
    u32 callbackUser;
    u32 fade;
} SndSpatialEntry;

typedef struct SndStudioInputLink {
    struct SndStudioInputLink *next;
    u8 pad04[0x10];
    f32 inputScale;
    u8 pad18[4];
    u8 sendLevel;
    s8 activeInput;
    u8 pad1e[2];
    SndSpatialEntry *source;
    SndSpatialEntry *target;
    u32 flags;
    u8 pad2c[8];
    u8 studioInput[4];
} SndStudioInputLink;

typedef struct SndRuntimeVoice {
    struct SndRuntimeVoice *next;
    u8 pad04[4];
    SndSpatialEntry *spatialEntry;
    u8 pad0c[8];
    u32 flags;
    u8 pad14[0x28];
    u32 handle;
} SndRuntimeVoice;

extern SndRuntimeVoice *s3dEmitterRoot;
extern SndSpatialListener *s3dListenerRoot;
extern SndSpatialEntry *s3dRoomRoot;
extern SndStudioInputLink *s3dDoorRoot;
extern u32 snd_used_studios;
extern u8 snd_base_studio;
extern u8 snd_max_studios;
extern f32 lbl_803E7880;
extern f32 lbl_803E7890;
extern f32 lbl_803E7894;
extern f64 lbl_803E7898;
extern f32 lbl_803E78A0;

extern void synthSendKeyOff(u32 handle);
extern void synthActivateStudio(u8 studio, int active, int unk);
extern void synthDeactivateStudio(u8 studio);
extern void synthAddStudioInput(u8 studio, u8 *input);
extern void synthRemoveStudioInput(u8 studio, u8 *input);

/*
 * fn_8027F2AC - large pre-mix processing (~1944 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027F2AC(void) {}
#pragma dont_inline reset

/*
 * Update average squared distance from each active spatial entry to all
 * registered listeners.
 */
#pragma dont_inline on
void fn_8027FA44(void)
{
    SndSpatialListener *listener;
    SndSpatialEntry *entry;
    u32 listenerCount;

    listenerCount = 0;
    for (listener = s3dListenerRoot; listener != NULL; listener = listener->next) {
        listenerCount++;
    }

    if (listenerCount != 0) {
        for (entry = s3dRoomRoot; entry != NULL; entry = entry->next) {
            f32 distanceSq;

            listener = s3dListenerRoot;
            distanceSq = lbl_803E7880;
            if (entry->assignedVoice != -1) {
                for (; listener != NULL; listener = listener->next) {
                    f32 dx = entry->x - listener->x;
                    f32 dy = entry->y - listener->y;
                    f32 dz = entry->z - listener->z;

                    distanceSq = distanceSq + dz * dz + dx * dx + dy * dy;
                }
                entry->averageDistanceSq = distanceSq / (f32)listenerCount;
            }
        }
    }
}
#pragma dont_inline reset

/*
 * Allocate scarce studio voices to spatial entries and update their
 * activation fade state.
 */
#pragma dont_inline on
void fn_8027FB08(void)
{
    SndSpatialEntry *entry;
    SndSpatialListener *listener;
    u32 listenerCount;

    fn_8027FA44();

    listenerCount = 0;
    for (listener = s3dListenerRoot; listener != NULL; listener = listener->next) {
        listenerCount++;
    }

    if (listenerCount != 0) {
        for (entry = s3dRoomRoot; entry != NULL; entry = entry->next) {
            if (entry->assignedVoice == -1) {
                SndSpatialEntry *evictedEntry;
                u32 studioCount;
                f32 distanceSq;
                int listenerOwned;

                distanceSq = lbl_803E7880;
                for (listener = s3dListenerRoot; listener != NULL; listener = listener->next) {
                    f32 dx = entry->x - listener->x;
                    f32 dy = entry->y - listener->y;
                    f32 dz = entry->z - listener->z;

                    distanceSq = distanceSq + dz * dz + dx * dx + dy * dy;
                }
                listenerOwned = false;
                distanceSq = distanceSq / (f32)listenerCount;
                for (listener = s3dListenerRoot; listener != NULL; listener = listener->next) {
                    if (listener->entry == entry) {
                        listenerOwned = true;
                        break;
                    }
                }

                studioCount = snd_max_studios;
                if (((1u << studioCount) - 1) == (((1u << studioCount) - 1) & snd_used_studios)) {
                    f32 worstDistance = lbl_803E7890;
                    SndRuntimeVoice *voice;
                    SndSpatialEntry *scanEntry;

                    for (scanEntry = s3dRoomRoot; scanEntry != NULL; scanEntry = scanEntry->next) {
                        if (scanEntry->assignedVoice != -1 &&
                            worstDistance < scanEntry->averageDistanceSq) {
                            evictedEntry = scanEntry;
                            worstDistance = scanEntry->averageDistanceSq;
                        }
                    }
                    if (!listenerOwned && worstDistance <= distanceSq) {
                        continue;
                    }
                    for (voice = s3dEmitterRoot; voice != NULL; voice = voice->next) {
                        if (voice->spatialEntry == evictedEntry) {
                            synthSendKeyOff(voice->handle);
                            voice->flags |= 0x80000;
                            voice->handle = 0xffffffff;
                        }
                    }
                    if (evictedEntry->evictCallback != NULL) {
                        evictedEntry->evictCallback(evictedEntry->assignedVoice);
                    }
                    synthDeactivateStudio(evictedEntry->assignedVoice);
                    entry->assignedVoice = evictedEntry->assignedVoice;
                    evictedEntry->assignedVoice = -1;
                    evictedEntry->flags = 0;
                } else {
                    int i;

                    for (i = 0; (studioCount != 0 && ((snd_used_studios & (1 << i)) != 0)); i++) {
                        studioCount--;
                    }
                    snd_used_studios |= 1 << i;
                    entry->assignedVoice = (s8)(i + snd_base_studio);
                }

                entry->averageDistanceSq = distanceSq;
                if (listenerOwned) {
                    entry->fade = 0x7f0000;
                } else {
                    entry->fade = 0;
                }
                if ((f32)(lbl_803E7894 * (f32)entry->fade) < lbl_803E7898) {
                    synthActivateStudio(entry->assignedVoice, 0, 0);
                } else {
                    synthActivateStudio(entry->assignedVoice, 1, 0);
                }
                if (entry->activateCallback != NULL) {
                    entry->activateCallback(entry->assignedVoice, entry->callbackUser);
                }
            } else {
                if ((entry->flags & 0x80000000) != 0) {
                    entry->fade += 0x40000;
                    if (entry->fade > 0x7effff) {
                        entry->fade = 0x7f0000;
                        entry->flags &= 0x7fffffff;
                    }
                    if ((f32)(lbl_803E7894 * (f32)entry->fade) < lbl_803E7898) {
                        synthActivateStudio(entry->assignedVoice, 0, 0);
                    } else {
                        synthActivateStudio(entry->assignedVoice, 1, 0);
                    }
                }
                if ((entry->flags & 0x40000000) != 0) {
                    entry->fade -= 0x40000;
                    if ((s32)entry->fade >= 0) {
                        entry->fade = 0;
                        entry->flags &= 0xbfffffff;
                    }
                    if ((f32)(lbl_803E7894 * (f32)entry->fade) < lbl_803E7898) {
                        synthActivateStudio(entry->assignedVoice, 0, 0);
                    } else {
                        synthActivateStudio(entry->assignedVoice, 1, 0);
                    }
                }
            }
        }
    }
}
#pragma dont_inline reset

/*
 * Update studio-input bridges between spatial entries as voices appear
 * and disappear.
 */
#pragma dont_inline on
void fn_8027FEE4(void)
{
    SndStudioInputLink *link;

    for (link = s3dDoorRoot; link != NULL; link = link->next) {
        if ((link->flags & 0x80000000) == 0) {
            if (link->source->assignedVoice != -1) {
                if (link->target->assignedVoice != -1) {
                    link->studioInput[1] = (s8)((f32)link->sendLevel * link->inputScale);
                    link->studioInput[2] = 0;
                    link->studioInput[0] = (s8)(lbl_803E78A0 * link->inputScale);
                    if ((link->flags & 1) == 0) {
                        link->studioInput[3] = link->source->assignedVoice;
                        synthAddStudioInput(link->target->assignedVoice, link->studioInput);
                    } else {
                        link->studioInput[3] = link->target->assignedVoice;
                        synthAddStudioInput(link->source->assignedVoice, link->studioInput);
                    }
                    link->flags |= 0x80000000;
                }
            }
        } else {
            s8 sourceVoice = link->source->assignedVoice;

            if (sourceVoice == -1 || link->target->assignedVoice == -1) {
                if ((sourceVoice != -1 && sourceVoice == link->activeInput) ||
                    (link->target->assignedVoice != -1 &&
                     link->target->assignedVoice == link->activeInput)) {
                    synthRemoveStudioInput(link->activeInput, link->studioInput);
                }
                link->flags &= 0x7fffffff;
            } else {
                link->studioInput[1] = (s8)((f32)link->sendLevel * link->inputScale);
                link->studioInput[2] = 0;
                link->studioInput[0] = (s8)(lbl_803E78A0 * link->inputScale);
            }
        }
    }
}
#pragma dont_inline reset
