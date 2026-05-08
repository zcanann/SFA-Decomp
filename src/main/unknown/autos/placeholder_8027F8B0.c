#include "ghidra_import.h"

typedef struct SndSpatialListener {
    struct SndSpatialListener *next;
    u8 pad04[0xc];
    f32 x;
    f32 y;
    f32 z;
} SndSpatialListener;

typedef struct SndSpatialEntry {
    struct SndSpatialEntry *next;
    u8 pad04[8];
    f32 x;
    f32 y;
    f32 z;
    f32 averageDistanceSq;
    s8 assignedVoice;
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

extern SndSpatialListener *lbl_803DE358;
extern SndSpatialEntry *lbl_803DE35C;
extern SndStudioInputLink *lbl_803DE360;
extern f32 lbl_803E7880;
extern f32 lbl_803E78A0;

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
    for (listener = lbl_803DE358; listener != NULL; listener = listener->next) {
        listenerCount++;
    }

    if (listenerCount != 0) {
        for (entry = lbl_803DE35C; entry != NULL; entry = entry->next) {
            f32 distanceSq;

            listener = lbl_803DE358;
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
 * fn_8027FB08 - large per-voice spatial update (~988 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027FB08(void) {}
#pragma dont_inline reset

/*
 * Update studio-input bridges between spatial entries as voices appear
 * and disappear.
 */
#pragma dont_inline on
void fn_8027FEE4(void)
{
    SndStudioInputLink *link;

    for (link = lbl_803DE360; link != NULL; link = link->next) {
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
