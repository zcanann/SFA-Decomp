#ifndef MAIN_DLL_DLL_00F8_LEVELNAME_H_
#define MAIN_DLL_DLL_00F8_LEVELNAME_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

typedef struct LevelnameState
{
    u8 pad0[0x8 - 0x0];
    s32 holdDuration;
    u8 triggerRadius;
    u8 unk0D;
    s16 gameBit;
    s16 holdTimer;
    s16 bannerY;
    u8 phase;
    u8 pad15[0x18 - 0x15];
} LevelnameState;

int LevelName_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int LevelName_getExtraSize(void);
int LevelName_getObjectTypeId(void);
void LevelName_free(void);
void LevelName_render(void);
void LevelName_hitDetect(void);
void LevelName_update(GameObject* obj);
void LevelName_init(GameObject* obj, int objDef);
void LevelName_release(void);
void LevelName_initialise(void);

#endif /* MAIN_DLL_DLL_00F8_LEVELNAME_H_ */
