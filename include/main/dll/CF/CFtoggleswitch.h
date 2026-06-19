#ifndef MAIN_DLL_CF_CFTOGGLESWITCH_H_
#define MAIN_DLL_CF_CFTOGGLESWITCH_H_

#include "ghidra_import.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"

#define TRICKY_GUARD_SPOT_DLL_ID 0x0120
#define TRICKY_GUARD_SPOT_CLASS_ID 0x0030
#define TRICKY_GUARD_SPOT_DEF_ID 0x04C6
#define TRICKY_GUARD_SPOT_OBJECT_DEF_BYTES 0xC0
#define TRICKY_GUARD_SPOT_PLACEMENT_BYTES 0x24
#define TRICKY_GUARD_SPOT_EXTRA_STATE_BYTES 0x08
#define TRICKY_GUARD_SPOT_GROUP 0x1E
#define TRICKY_GUARD_SPOT_ACTION 1
#define TRICKY_GUARD_SPOT_ACTION_PARAM 3
#define TRICKY_GUARD_SPOT_VISIBLE_HITBOX_FLAG 0x04
#define TRICKY_GUARD_SPOT_ACTIVE_HITBOX_FLAG 0x08

extern ObjectDescriptor gMagicCaveBottomObjDescriptor;
extern ObjectDescriptor gMagicCaveTopObjDescriptor;
extern ObjectDescriptor gTrickyGuardSpotObjDescriptor;
extern ObjectDescriptor gInfoTextObjDescriptor;
extern ObjectDescriptor gCCTestInfotObjDescriptor;
extern ObjectDescriptor gDeathGasObjDescriptor;

typedef struct TrickyGuardSpotObject TrickyGuardSpotObject;

typedef struct TrickyGuardSpotPlacement {
    ObjPlacement base;
    s8 initialYaw;
    u8 resetSeconds;
    s16 triggerRadius;
    u8 pad1C[0x1E - 0x1C];
    s16 rangeGameBit;
    u8 pad20[TRICKY_GUARD_SPOT_PLACEMENT_BYTES - 0x20];
} TrickyGuardSpotPlacement;

typedef struct TrickyGuardSpotStateFlags {
    u8 trickyInRange : 1; /* PPC bitfield maps to the high bit. */
    u8 flags : 7;
} TrickyGuardSpotStateFlags;

typedef struct TrickyGuardSpotState {
    s32 resetTimer;
    TrickyGuardSpotStateFlags flags;
    u8 pad05[TRICKY_GUARD_SPOT_EXTRA_STATE_BYTES - 0x05];
} TrickyGuardSpotState;

struct TrickyGuardSpotObject {
    ObjAnimComponent objAnim;
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    TrickyGuardSpotState *state;
};

STATIC_ASSERT(sizeof(TrickyGuardSpotPlacement) == TRICKY_GUARD_SPOT_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, initialYaw) == 0x18);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, resetSeconds) == 0x19);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(TrickyGuardSpotPlacement, rangeGameBit) == 0x1E);
STATIC_ASSERT(sizeof(TrickyGuardSpotStateFlags) == 0x01);
STATIC_ASSERT(sizeof(TrickyGuardSpotState) == TRICKY_GUARD_SPOT_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(TrickyGuardSpotState, resetTimer) == 0x00);
STATIC_ASSERT(offsetof(TrickyGuardSpotState, flags) == 0x04);
STATIC_ASSERT(offsetof(TrickyGuardSpotObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(TrickyGuardSpotObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(TrickyGuardSpotObject, state) == 0xB8);

void magiccavebottom_update(int *obj);
void FUN_8018aee4(void);
void FUN_8018af08(int param_1);
void FUN_8018af28(int param_1);
void FUN_8018af74(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8018b220(u16 *param_1);
void FUN_8018b224(void);
void FUN_8018b258(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9,u32 param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_8018b5a0(u64 param_1,u64 param_2,u64 param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9);
void FUN_8018b6ac(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8);
int magiccavetop_getExtraSize(void);
int trickyguardspot_getExtraSize(void);
int infotext_getExtraSize(void);
int cctestinfot_getExtraSize(void);
int deathgas_getExtraSize(void);
void trickyguardspot_free(TrickyGuardSpotObject *obj);
void trickyguardspot_render(void);
void trickyguardspot_update(TrickyGuardSpotObject *obj);
void trickyguardspot_init(TrickyGuardSpotObject *obj, TrickyGuardSpotPlacement *def);

#endif /* MAIN_DLL_CF_CFTOGGLESWITCH_H_ */
