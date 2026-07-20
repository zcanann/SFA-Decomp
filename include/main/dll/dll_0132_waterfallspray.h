#ifndef MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_
#define MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_

#include "main/game_object.h"
#include "main/obj_placement.h"

#define WATERFALLSPRAY_ALT_SFX_DEF_MIN 0x4BE5C
#define WATERFALLSPRAY_ALT_SFX_DEF_END 0x4BE5E
#define WATERFALLSPRAY_DEFAULT_SFX_A 0x2AF
#define WATERFALLSPRAY_DEFAULT_SFX_B 0x2B2
#define WATERFALLSPRAY_ALT_SFX_A 0x489
#define WATERFALLSPRAY_ALT_SFX_B 0x48A

#define WATERFALLSPRAY_FLAG_EFFECT_320 0x01
#define WATERFALLSPRAY_FLAG_EFFECT_321 0x02
#define WATERFALLSPRAY_FLAG_EFFECT_322 0x04
#define WATERFALLSPRAY_FLAG_EFFECT_351 0x08
#define WATERFALLSPRAY_FLAG_SFX_DISABLED 0x10

typedef struct WaterFallSpraySetup
{
    ObjPlacement base;
    s16 gameBit;
    s8 rotZ;
    s8 rotY;
    s8 rotX;
    u8 randomExtentX;
    u8 randomExtentZ;
    u8 randomExtentY;
    u8 triggerRadius;
    u8 pad21[2];
    u8 flags;
    u8 emitCount;
} WaterFallSpraySetup;

typedef struct WaterFallSprayState
{
    u32 sfxIdA;
    u32 sfxIdB;
} WaterFallSprayState;

STATIC_ASSERT(offsetof(WaterFallSpraySetup, gameBit) == 0x18);
STATIC_ASSERT(offsetof(WaterFallSpraySetup, rotZ) == 0x1a);
STATIC_ASSERT(offsetof(WaterFallSpraySetup, randomExtentX) == 0x1d);
STATIC_ASSERT(offsetof(WaterFallSpraySetup, triggerRadius) == 0x20);
STATIC_ASSERT(offsetof(WaterFallSpraySetup, flags) == 0x23);
STATIC_ASSERT(offsetof(WaterFallSpraySetup, emitCount) == 0x24);
STATIC_ASSERT(sizeof(WaterFallSprayState) == 0x08);

void WaterFallSpray_free(GameObject* obj);
void WaterFallSpray_init(GameObject* obj, WaterFallSpraySetup* setup);
void WaterFallSpray_render(void);
void WaterFallSpray_update(GameObject* obj);
int WaterFallSpray_getExtraSize(void);
int WaterFallSpray_SeqFn(GameObject* obj);

#endif /* MAIN_DLL_DLL_0132_WATERFALLSPRAY_H_ */
