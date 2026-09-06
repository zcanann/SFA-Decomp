#ifndef MAIN_NEWSHADOWS_AUDIO_API_H_
#define MAIN_NEWSHADOWS_AUDIO_API_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/objanim.h"
#include "main/dll/curves_collision_state.h"

#define SURFACE_SFX_BANK_COUNT         9
#define SURFACE_SFX_COLUMN_COUNT       10
#define SURFACE_SFX_SURFACE_TYPE_COUNT 0x23

typedef struct SurfaceSfxTable {
    u16 triggers[SURFACE_SFX_BANK_COUNT][SURFACE_SFX_COLUMN_COUNT];
    u8 surfaceColumns[SURFACE_SFX_SURFACE_TYPE_COUNT];
} SurfaceSfxTable;

STATIC_ASSERT(offsetof(SurfaceSfxTable, triggers) == 0);
STATIC_ASSERT(sizeof(((SurfaceSfxTable*)0)->triggers[0]) == 0x14);
STATIC_ASSERT(offsetof(SurfaceSfxTable, surfaceColumns) == 0xB4);
STATIC_ASSERT(sizeof(SurfaceSfxTable) == 0xD8);

extern SurfaceSfxTable gSurfaceSfxTable;

u16* surfaceSfxGetRecord(u32 soundId);
int surfaceSfxSelectTrigger(u8 surfaceType, u8 soundId);
void objAudioDispatchEventMask(GameObject* obj, int eventMask, u8 type, void* points, CurvesCollisionState* collision,
                               f32 speed, f32 scale);
void objAudioDispatchAnimEvents(GameObject* obj, ObjAnimEventList* events, u8 type, void* points,
                                CurvesCollisionState* collision, f32 speed, f32 scale);

#endif /* MAIN_NEWSHADOWS_AUDIO_API_H_ */
