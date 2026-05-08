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

extern SndSpatialListener *lbl_803DE358;
extern SndSpatialEntry *lbl_803DE35C;
extern f32 lbl_803E7880;

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
 * fn_8027FEE4 - large reverb/3D-audio walker (~432 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8027FEE4(void) {}
#pragma dont_inline reset
