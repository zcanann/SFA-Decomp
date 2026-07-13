#ifndef MAIN_DLL_DLL_0104_SMALLBASKET_H_
#define MAIN_DLL_DLL_0104_SMALLBASKET_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

/* Small-basket per-object extra state. */
typedef struct CfperchState {
    s16 carryAngle;      /* 0x0 low half of the 0x100010 carry message */
    s16 carryParam;      /* 0x2 high half of the 0x100010 carry message */
    u8 unk4[0x5 - 0x4];
    s8 carryState;       /* 0x5 carry/throw state machine: 0 idle, 1 grabbed, 2 carried */
    u8 carryAttached;    /* 0x6 set while held by player; gates the per-frame carry message */
    u8 unk7[0x9 - 0x7];
    u8 throwState;       /* 0x9 in-flight mode: 0 none, 1 thrown, 2 dropped */
    s16 disableTimer;    /* 0xA post-action hide/disable countdown */
    s16 leashRange;      /* 0xC carry leash range from placement origin */
    s16 randomTimer;
    s16 sfxId;
    s16 respawnTimer;
    int hiddenTimer;     /* 0x14 hide/fade countdown while disabled */
    int respawnDelay;    /* 0x18 configured respawn delay */
    s16 enableGameBit;
    u8 subtype;          /* 0x1E object subtype, selects ambient sfx */
    u8 unk1F;
    u8 disguiseGated;    /* 0x20 set for seqId 0x662 */
    u8 unk21[0x28 - 0x21];
} CfperchState;

STATIC_ASSERT(offsetof(CfperchState, hiddenTimer) == 0x14);

void FUN_801816f8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,u32 param_10,int param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
int SmallBasket_getExtraSize(void);
void objThrowFn_80182504(GameObject* obj);

extern ObjectDescriptor gSmallBasketObjDescriptor;

#endif /* MAIN_DLL_DLL_0104_SMALLBASKET_H_ */
