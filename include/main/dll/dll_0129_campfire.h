#ifndef MAIN_DLL_DLL_0129_CAMPFIRE_H_
#define MAIN_DLL_DLL_0129_CAMPFIRE_H_

#include "main/game_object.h"
#include "main/model_light.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define CAMPFIRE_STATE_GLOBAL_GAMEBIT_SET    0x1
#define CAMPFIRE_STATE_PLACEMENT_GAMEBIT_SET 0x4

typedef struct CampFireSetup
{
    ObjPlacement base;
    s16 gameBit;
    u8 scalePercent;
    u8 unk1B;
} CampFireSetup;

typedef struct CampFireState
{
    ModelLightStruct* light;
    f32 dayTimer;
    f32 nightTimer;
    s16 gameBit;
    u8 pad0E[2];
    u8 unk10;
    u8 flags;
    u8 sfxPlaying;
    u8 unk13;
} CampFireState;

STATIC_ASSERT(offsetof(CampFireSetup, gameBit) == 0x18);
STATIC_ASSERT(offsetof(CampFireSetup, scalePercent) == 0x1a);
STATIC_ASSERT(offsetof(CampFireSetup, unk1B) == 0x1b);
STATIC_ASSERT(sizeof(CampFireSetup) == 0x1c);
STATIC_ASSERT(offsetof(CampFireState, light) == 0x00);
STATIC_ASSERT(offsetof(CampFireState, dayTimer) == 0x04);
STATIC_ASSERT(offsetof(CampFireState, nightTimer) == 0x08);
STATIC_ASSERT(offsetof(CampFireState, gameBit) == 0x0c);
STATIC_ASSERT(offsetof(CampFireState, unk10) == 0x10);
STATIC_ASSERT(offsetof(CampFireState, flags) == 0x11);
STATIC_ASSERT(offsetof(CampFireState, sfxPlaying) == 0x12);
STATIC_ASSERT(sizeof(CampFireState) == 0x14);

int CampFire_getExtraSize(void);
int CampFire_getObjectTypeId(void);
void CampFire_free(GameObject* obj);
void CampFire_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void CampFire_update(GameObject* obj);
void CampFire_init(GameObject* obj, CampFireSetup* setup);

extern ObjectDescriptor gCampFireObjDescriptor;

#endif /* MAIN_DLL_DLL_0129_CAMPFIRE_H_ */
