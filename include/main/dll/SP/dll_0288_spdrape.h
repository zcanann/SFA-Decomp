#ifndef MAIN_DLL_SP_DLL_0288_SPDRAPE_H_
#define MAIN_DLL_SP_DLL_0288_SPDRAPE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct SpdrapeObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 facingByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1A - 0x19];
    s16 motionScaleNum; /* 0x1A: root-motion scale numerator (0 = leave default) */
    u8 pad1C[0x20 - 0x1C];
} SpdrapeObjectDef;

STATIC_ASSERT(sizeof(SpdrapeObjectDef) == 0x20);

typedef struct SpdrapeState
{
    f32 animSpeed;    /* 0x00: move-advance speed */
    f32 planeNormalX; /* 0x04: drape-plane normal X */
    f32 planeNormalZ; /* 0x08: drape-plane normal Z */
    f32 planeD;       /* 0x0C: drape-plane offset */
    s32 moveTable;    /* 0x10: &u8[] move-id table for the current swing dir */
    s16 sfxTimer;     /* 0x14: countdown to the next idle rustle sfx */
    u8 moveActive;    /* 0x16: ObjAnim_AdvanceCurrentMove result */
    u8 pad17[0x18 - 0x17];
} SpdrapeState;

STATIC_ASSERT(sizeof(SpdrapeState) == 0x18);

int spdrape_getExtraSize(void);
int spdrape_getObjectTypeId(void);
void spdrape_free(void);
void spdrape_render(void);
void spdrape_hitDetect(void);
void spdrape_update(int obj);
void spdrape_init(int* obj, u8* def);
void spdrape_release(void);
void spdrape_initialise(void);

#endif /* MAIN_DLL_SP_DLL_0288_SPDRAPE_H_ */
