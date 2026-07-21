#ifndef MAIN_DLL_DLL_00F8_LEVELNAME_H_
#define MAIN_DLL_DLL_00F8_LEVELNAME_H_

#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct LevelNamePlacement
{
    ObjPlacement base;
    s16 enableGameBit;
    u8 reserved1A[2];
    s32 textId;
    u8 triggerRadius;
    u8 reserved21[3];
} LevelNamePlacement;

typedef struct LevelNameState
{
    s32 textRecord;
    s32 textData;
    s32 holdDuration;
    u8 triggerRadius;
    u8 reserved0D;
    s16 enableGameBit;
    s16 elapsedFrames;
    s16 bannerY;
    u8 phase;
    u8 reserved15[3];
} LevelNameState;

STATIC_ASSERT(offsetof(LevelNamePlacement, enableGameBit) == 0x18);
STATIC_ASSERT(offsetof(LevelNamePlacement, textId) == 0x1c);
STATIC_ASSERT(offsetof(LevelNamePlacement, triggerRadius) == 0x20);
STATIC_ASSERT(sizeof(LevelNamePlacement) == 0x24);
STATIC_ASSERT(offsetof(LevelNameState, holdDuration) == 0x8);
STATIC_ASSERT(offsetof(LevelNameState, triggerRadius) == 0xc);
STATIC_ASSERT(offsetof(LevelNameState, enableGameBit) == 0xe);
STATIC_ASSERT(offsetof(LevelNameState, elapsedFrames) == 0x10);
STATIC_ASSERT(offsetof(LevelNameState, bannerY) == 0x12);
STATIC_ASSERT(offsetof(LevelNameState, phase) == 0x14);
STATIC_ASSERT(sizeof(LevelNameState) == 0x18);

int LevelName_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int LevelName_getExtraSize(void);
int LevelName_getObjectTypeId(void);
void LevelName_free(void);
void LevelName_render(void);
void LevelName_hitDetect(void);
void LevelName_update(GameObject* obj);
void LevelName_init(GameObject* obj, LevelNamePlacement* placement);
void LevelName_release(void);
void LevelName_initialise(void);

extern ObjectDescriptor gLevelNameObjDescriptor;

#endif /* MAIN_DLL_DLL_00F8_LEVELNAME_H_ */
