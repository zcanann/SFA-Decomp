#ifndef MAIN_DLL_CF_CFCHUCKOBJ_H_
#define MAIN_DLL_CF_CFCHUCKOBJ_H_

#include "ghidra_import.h"
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/dll/curve_walker.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

extern ObjectDescriptor gAreaFXEmitObjDescriptor;
extern ObjectDescriptor12 gLFXEmitterObjDescriptor;

#define AREAFXEMIT_DLL_ID 0x0130
#define AREAFXEMIT_CLASS_ID 0x0067
#define AREAFXEMIT_DEF_ID 0x05A8
#define TAREAFXEMIT_DEF_ID 0x05AA
#define AREAFXEMIT_OBJECT_DEF_BYTES 0xA0
#define AREAFXEMIT_PLACEMENT_BYTES 0x28
#define AREAFXEMIT_EXTRA_STATE_BYTES 0x20
#define AREAFXEMIT_SPAWN_LOCAL_WORLD 0
#define AREAFXEMIT_SPAWN_OBJECT_RESOURCE 1
#define AREAFXEMIT_SPAWN_OBJECT_RESOURCE_ALT 2
#define AREAFXEMIT_SPAWN_LOCAL_OBJECT 3
#define AREAFXEMIT_APPROACH_BURST_COUNT 0x23
#define LFXEMITTER_DLL_ID 0x012D
#define LFXEMITTER_CLASS_ID 0x0060
#define LFXEMITTER_DEF_ID 0x04B0
#define LFXEMITTER_OBJECT_DEF_BYTES 0xA0
#define LFXEMITTER_PLACEMENT_BYTES 0x28
#define LFXEMITTER_EXTRA_STATE_BYTES 0x124
#define LFXEMITTER_CURVE_RECORD_BYTES 0x108
#define LFXEMITTER_CONFIG_BYTES 0x28
#define LFXEMITTER_OBJ_GROUP 0x1C
#define LFXEMITTER_FLAG_FOLLOW_CURVE 1
#define LFXEMITTER_FLAG_DAMP_Y_VELOCITY 2

typedef struct AreaFxEmitObject AreaFxEmitObject;
typedef struct LfxEmitterObject LfxEmitterObject;
typedef int (*AreaFxEmitSeqCallback)(AreaFxEmitObject *obj, int unused, ObjAnimUpdateState *animUpdate);

typedef struct AreaFxEmitPlacement {
    ObjPlacement base;
    s8 triggerRadius;
    s8 initialRoll;
    s8 initialPitch;
    s8 initialYaw;
    u8 extentX;
    u8 extentZ;
    u8 extentY;
    u8 emitType;
    u16 effectId;
    s16 emitCount;
    s16 enableBit;
    s16 stopBit;
} AreaFxEmitPlacement;

/*
 * Per-object extra state for the areafxemit volume particle emitter
 * (areafxemit_getExtraSize == 0x20).
 */
typedef struct AreaFxEmitState {
    f32 triggerRadius; /* (s8)setup[0x18] << 2; sentinel value = always emit */
    f32 lastDistance; /* player distance at the last emit check */
    u8 emitType; /* setup[0x1f]; 4/6 = world-positioned spawn (flag 0x200001), >3 bursts on approach */
    u8 pad09;
    u16 effectId;
    s16 emitCount; /* setup+0x22; >0: spawns per emit; <=0: negated re-emit cooldown; 0 also suppresses */
    s16 enableBit; /* gamebit gate, -1 = always on */
    s16 stopBit; /* gamebit; once set the emitter suppresses */
    s16 suppressed;
    u16 extentX; /* setup[0x1c] << 2 -- random offset half-extents */
    u16 extentZ; /* setup[0x1d] << 2 */
    u16 extentY; /* setup[0x1e] << 2 */
    s16 emitAngles[3]; /* yaw/pitch/roll, mirrored to obj+0/2/4 */
} AreaFxEmitState;

struct AreaFxEmitObject {
    ObjAnimComponent objAnim;
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    AreaFxEmitState *state;
    AreaFxEmitSeqCallback seqCallback;
    u8 padC0[0xF4 - 0xC0];
    s32 emitCooldown;
};

STATIC_ASSERT(sizeof(AreaFxEmitPlacement) == AREAFXEMIT_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, triggerRadius) == 0x18);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, initialRoll) == 0x19);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, initialPitch) == 0x1A);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, initialYaw) == 0x1B);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, extentX) == 0x1C);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, extentZ) == 0x1D);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, extentY) == 0x1E);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, emitType) == 0x1F);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, effectId) == 0x20);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, emitCount) == 0x22);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, enableBit) == 0x24);
STATIC_ASSERT(offsetof(AreaFxEmitPlacement, stopBit) == 0x26);
STATIC_ASSERT(sizeof(AreaFxEmitState) == AREAFXEMIT_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(AreaFxEmitState, lastDistance) == 0x04);
STATIC_ASSERT(offsetof(AreaFxEmitState, emitType) == 0x08);
STATIC_ASSERT(offsetof(AreaFxEmitState, effectId) == 0x0A);
STATIC_ASSERT(offsetof(AreaFxEmitState, emitCount) == 0x0C);
STATIC_ASSERT(offsetof(AreaFxEmitState, enableBit) == 0x0E);
STATIC_ASSERT(offsetof(AreaFxEmitState, stopBit) == 0x10);
STATIC_ASSERT(offsetof(AreaFxEmitState, suppressed) == 0x12);
STATIC_ASSERT(offsetof(AreaFxEmitState, extentX) == 0x14);
STATIC_ASSERT(offsetof(AreaFxEmitState, extentZ) == 0x16);
STATIC_ASSERT(offsetof(AreaFxEmitState, extentY) == 0x18);
STATIC_ASSERT(offsetof(AreaFxEmitState, emitAngles) == 0x1A);
STATIC_ASSERT(offsetof(AreaFxEmitObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(AreaFxEmitObject, state) == 0xB8);
STATIC_ASSERT(offsetof(AreaFxEmitObject, seqCallback) == 0xBC);
STATIC_ASSERT(offsetof(AreaFxEmitObject, emitCooldown) == 0xF4);

/*
 * 0x28-byte lfxemitter spawn config record (the lbl_803AC7B0 / mmAlloc copy
 * format produced by fn_8018FF48 and consumed by FUN_8018f650). spawnType
 * selects between the gPartfxInterface spawn paths and the FUN_80006b14
 * effect-bank paths; the rangeX/Y/Z fields seed randomGetRange jitter and
 * posBlock* feed FUN_80017748.
 */
typedef struct LfxEmitterConfig {
    u8 pad00[0x08];
    u8 spawnType;
    u8 pad09;
    u16 effectId;
    s16 spawnCount;
    u16 recordCount; /* count of loaded config records (lfxemitter_initialise seeds 10000) */
    u8 pad10[0x14 - 0x10];
    u16 rangeX;
    u16 rangeZ;
    u16 rangeY;
    u16 posBlock0;
    u16 posBlock1;
    s16 posBlock2;
    u8 pad20[0x28 - 0x20];
} LfxEmitterConfig;

STATIC_ASSERT(sizeof(LfxEmitterConfig) == LFXEMITTER_CONFIG_BYTES);
STATIC_ASSERT(offsetof(LfxEmitterConfig, spawnType) == 0x08);
STATIC_ASSERT(offsetof(LfxEmitterConfig, effectId) == 0x0A);
STATIC_ASSERT(offsetof(LfxEmitterConfig, spawnCount) == 0x0C);
STATIC_ASSERT(offsetof(LfxEmitterConfig, recordCount) == 0x0E);
STATIC_ASSERT(offsetof(LfxEmitterConfig, rangeX) == 0x14);
STATIC_ASSERT(offsetof(LfxEmitterConfig, rangeZ) == 0x16);
STATIC_ASSERT(offsetof(LfxEmitterConfig, rangeY) == 0x18);
STATIC_ASSERT(offsetof(LfxEmitterConfig, posBlock0) == 0x1A);
STATIC_ASSERT(offsetof(LfxEmitterConfig, posBlock1) == 0x1C);
STATIC_ASSERT(offsetof(LfxEmitterConfig, posBlock2) == 0x1E);

typedef struct LfxEmitterPlacement {
    u8 pad00[0x08];
    f32 initialX;
    f32 initialY;
    f32 initialZ;
    u8 pad14[0x18 - 0x14];
    s16 spinRoll;
    s16 spinPitch;
    s16 spinYaw;
    s16 configIndex;
    s16 lifeTimer;
    s16 enableBit;
    u8 followCurve;
    s8 curveSpeed;
    u8 pad26[2];
} LfxEmitterPlacement;

/*
 * Per-object extra state for the lfxemitter curve-following emitter
 * (lfxemitter_getExtraSize == 0x124). The leading 0x108 bytes are the
 * rom-curve walker record handed to Curve_AdvanceAlongPath / gRomCurveInterface.
 */
typedef struct LfxEmitterState {
    RomCurveWalker curve;
    void *config; /* mmAlloc(0x28) copy of the lbl_803AC7B0-format record */
    f32 curveSpeed; /* placement curveSpeed / lbl_803E3E84 */
    s16 lifeTimer; /* frames until Obj_FreeObject when armed */
    s16 configIndex; /* tab entry index */
    s16 unk114; /* -2 at init */
    s16 enableBit; /* gamebit gate, -1 = always on */
    s16 spinRoll;
    s16 spinPitch;
    s16 spinYaw;
    u8 hasLifeTimer;
    u8 configLoaded;
    u8 flags; /* LFXEMITTER_FLAG_* */
    u8 pad121[3];
} LfxEmitterState;

struct LfxEmitterObject {
    ObjAnimComponent objAnim;
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    LfxEmitterState *state;
};

STATIC_ASSERT(sizeof(LfxEmitterPlacement) == LFXEMITTER_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, initialX) == 0x08);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, spinRoll) == 0x18);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, spinPitch) == 0x1A);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, spinYaw) == 0x1C);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, configIndex) == 0x1E);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, lifeTimer) == 0x20);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, enableBit) == 0x22);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, followCurve) == 0x24);
STATIC_ASSERT(offsetof(LfxEmitterPlacement, curveSpeed) == 0x25);
STATIC_ASSERT(sizeof(LfxEmitterState) == LFXEMITTER_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(LfxEmitterState, curve) == 0x00);
STATIC_ASSERT(offsetof(LfxEmitterState, curve.atSegmentEnd) == 0x10);
STATIC_ASSERT(offsetof(LfxEmitterState, curve.posX) == 0x68);
STATIC_ASSERT(offsetof(LfxEmitterState, config) == 0x108);
STATIC_ASSERT(offsetof(LfxEmitterState, curveSpeed) == 0x10C);
STATIC_ASSERT(offsetof(LfxEmitterState, flags) == 0x120);
STATIC_ASSERT(offsetof(LfxEmitterObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(LfxEmitterObject, state) == 0xB8);

void fxemit_init(FxEmitObject *obj, FxEmitPlacement *setup);
void FUN_8018f158(u32 param_1);
void FUN_8018f1b4(short *param_1);
void FUN_8018f4fc(u16 *param_1,int param_2);
void FUN_8018f500(void);
void FUN_8018f650(void);
int FUN_8018fca4(int obj, int unused, ObjAnimUpdateState *animUpdate);
void FUN_8018fd14(int obj);
void FUN_8018fd48(int param_1);
void FUN_8018fec4(u16 *param_1,int param_2);
void FUN_8018fec8(u16 *param_1,u16 *param_2);
void FUN_8018ffbc(int param_1);
void areafxemit_emitBurst(AreaFxEmitObject *obj, int count);
void areafxemit_emitEffect(AreaFxEmitObject *obj);
void fn_8018FF48(u16* src, u16* dst);
void FUN_80190004(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 short *param_9);
void FUN_80190008(int param_1,int param_2);

int areafxemit_getExtraSize(void);
int areafxemit_getObjectTypeId(void);
void areafxemit_free(AreaFxEmitObject *obj);
void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void areafxemit_hitDetect(void);
void areafxemit_update(AreaFxEmitObject *obj);
void areafxemit_init(AreaFxEmitObject *obj, AreaFxEmitPlacement *setup);
void areafxemit_release(void);
void areafxemit_initialise(void);

int lfxemitter_func0B(LfxEmitterObject *obj);
int lfxemitter_setScale(void);
int lfxemitter_getExtraSize(void);
int lfxemitter_getObjectTypeId(void);
void lfxemitter_free(LfxEmitterObject *obj);
void lfxemitter_render(void);
void lfxemitter_hitDetect(void);
void lfxemitter_update(LfxEmitterObject *obj);
void lfxemitter_init(LfxEmitterObject *obj, LfxEmitterPlacement *setup);
void lfxemitter_release(void);
void lfxemitter_initialise(void);

void warpPadPlayerStandingOn(int obj);
void warpPadFn_8019042c(int obj);

#endif /* MAIN_DLL_CF_CFCHUCKOBJ_H_ */
