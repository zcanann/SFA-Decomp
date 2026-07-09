#ifndef MAIN_DLL_DLL_00EE_EFFECTBOX_H_
#define MAIN_DLL_DLL_00EE_EFFECTBOX_H_

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

int EffectBox_getExtraSize(void);
int EffectBox_getObjectTypeId(void);
void EffectBox_free(void);
void EffectBox_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void EffectBox_hitDetect(void);
void EffectBox_update(struct GameObject* obj);
void EffectBox_init(int obj, EffectboxPlacement* def);
void EffectBox_release(void);
void EffectBox_initialise(void);

#endif /* MAIN_DLL_DLL_00EE_EFFECTBOX_H_ */
