#ifndef MAIN_DLL_DLL_00EE_EFFECTBOX_H_
#define MAIN_DLL_DLL_00EE_EFFECTBOX_H_

#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

typedef struct EffectboxPlacement
{
    ObjPlacement base;
    u8 rotYaw;    /* 0x18: yaw in 1/256 turns */
    u8 rotPitch;  /* 0x19: pitch in 1/256 turns */
    u8 extentX;   /* 0x1A */
    u8 extentY;   /* 0x1B */
    u8 extentZ;   /* 0x1C */
    u8 actionArg; /* 0x1D: action argument */
    u8 pad1E;
    u8 gameBitValue;  /* 0x1F: gate value compared against the game bit */
    s16 gameBitIndex; /* 0x20: game bit index */
    u8 targetMode;    /* 0x22: EFFECTBOX_TARGET_* candidate set */
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;

STATIC_ASSERT(offsetof(EffectboxPlacement, rotYaw) == 0x18);
STATIC_ASSERT(offsetof(EffectboxPlacement, extentX) == 0x1A);
STATIC_ASSERT(offsetof(EffectboxPlacement, actionArg) == 0x1D);
STATIC_ASSERT(offsetof(EffectboxPlacement, gameBitValue) == 0x1F);
STATIC_ASSERT(offsetof(EffectboxPlacement, gameBitIndex) == 0x20);
STATIC_ASSERT(offsetof(EffectboxPlacement, targetMode) == 0x22);
STATIC_ASSERT(sizeof(EffectboxPlacement) == 0x28);

int EffectBox_getExtraSize(void);
int EffectBox_getObjectTypeId(void);
void EffectBox_free(GameObject* obj);
void EffectBox_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void EffectBox_hitDetect(void);
void EffectBox_update(GameObject* obj);
void EffectBox_init(GameObject* obj, EffectboxPlacement* def);
void EffectBox_release(void);
void EffectBox_initialise(void);

#endif /* MAIN_DLL_DLL_00EE_EFFECTBOX_H_ */
