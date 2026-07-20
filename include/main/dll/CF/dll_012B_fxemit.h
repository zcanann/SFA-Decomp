#ifndef MAIN_DLL_CF_CFTREASSHARPY_H_
#define MAIN_DLL_CF_CFTREASSHARPY_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "global.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_internal.h"
#include "main/objanim_update.h"

extern ObjectDescriptor gFXEmitObjDescriptor;

#define FXEMIT_DLL_ID                0x012B
#define FXEMIT_CLASS_ID              0x006B
#define FXEMIT_DEF_ID                0x05A7
#define FXEMIT_OBJECT_DEF_BYTES      0xA0
#define FXEMIT_PLACEMENT_BYTES       0x2C
#define FXEMIT_EXTRA_STATE_BYTES     0x20
#define FXEMIT_SPAWN_MODE_OBJECT     0
#define FXEMIT_SPAWN_MODE_OBJECT_ALT 1
#define FXEMIT_SPAWN_MODE_WORLD      2
#define FXEMIT_SPAWN_MODE_NONE       3
#define FXEMIT_ROTATION_STEP_AUTO    0x7F
#define FXEMIT_SFX_SUPPRESS          0xFF

typedef struct FxEmitObject FxEmitObject;
typedef int (*FxEmitSeqCallback)(FxEmitObject* obj, int unused, ObjAnimUpdateState* animUpdate);

typedef struct FxEmitPlacement
{
    ObjPlacement base;
    s8 triggerRadius;
    s8 effectMode;
    s16 effectId;
    s16 emitCount;
    s16 enableBit;
    s16 stopBit;
    s8 initialRoll;
    s8 initialPitch;
    s8 initialYaw;
    s8 rollStep;
    s8 pitchStep;
    s8 yawStep;
    u8 spawnMode;
    u8 sfxPeriod;
    s16 sfxId;
} FxEmitPlacement;

/*
 * Per-object extra state for the fxemit particle emitter
 * (FxEmit_getExtraSize == 0x20). init lives in CFchuckobj.c,
 * the rest of the family in CFTreasSharpy.c.
 */
typedef struct FxEmitState
{
    f32 triggerRadius; /* (s8)setup[0x18] << 2; sentinel value = always emit */
    f32 initialX;      /* object X at init */
    s16 effectMode;    /* 0 partfx, 1 resource id+0x58, 2 resource id+0xAB */
    s16 effectId;
    s16 altEffectId; /* spawned instead when emitCount <= 0 on the args path */
    s16 emitCount;   /* >0: spawns per emit; <=0: negated re-emit cooldown frames */
    u8 pad10[2];
    s16 startDelay; /* rand(0,10), counts down by timeDelta */
    s16 enableBit;  /* gamebit gate, -1 = always on */
    s16 stopBit;    /* gamebit; once set the emitter suppresses */
    s16 suppressed;
    s16 sfxTimer; /* def[0x29]*100, counts down by framesThisStep */
    u8 seqToggle; /* flipped by anim event 2 */
    u8 pad1D[3];
} FxEmitState;

struct FxEmitObject
{
    ObjAnimComponent objAnim;
    u16 objectFlags;
    u8 padB2[0xB8 - 0xB2];
    FxEmitState* state;
    FxEmitSeqCallback seqCallback;
    u8 padC0[0xF4 - 0xC0];
    s32 emitCooldown;
};

STATIC_ASSERT(sizeof(FxEmitPlacement) == FXEMIT_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(FxEmitPlacement, triggerRadius) == 0x18);
STATIC_ASSERT(offsetof(FxEmitPlacement, effectMode) == 0x19);
STATIC_ASSERT(offsetof(FxEmitPlacement, effectId) == 0x1A);
STATIC_ASSERT(offsetof(FxEmitPlacement, emitCount) == 0x1C);
STATIC_ASSERT(offsetof(FxEmitPlacement, enableBit) == 0x1E);
STATIC_ASSERT(offsetof(FxEmitPlacement, stopBit) == 0x20);
STATIC_ASSERT(offsetof(FxEmitPlacement, initialRoll) == 0x22);
STATIC_ASSERT(offsetof(FxEmitPlacement, initialPitch) == 0x23);
STATIC_ASSERT(offsetof(FxEmitPlacement, initialYaw) == 0x24);
STATIC_ASSERT(offsetof(FxEmitPlacement, rollStep) == 0x25);
STATIC_ASSERT(offsetof(FxEmitPlacement, pitchStep) == 0x26);
STATIC_ASSERT(offsetof(FxEmitPlacement, yawStep) == 0x27);
STATIC_ASSERT(offsetof(FxEmitPlacement, spawnMode) == 0x28);
STATIC_ASSERT(offsetof(FxEmitPlacement, sfxPeriod) == 0x29);
STATIC_ASSERT(offsetof(FxEmitPlacement, sfxId) == 0x2A);
STATIC_ASSERT(sizeof(FxEmitState) == FXEMIT_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(FxEmitState, initialX) == 0x04);
STATIC_ASSERT(offsetof(FxEmitState, effectMode) == 0x08);
STATIC_ASSERT(offsetof(FxEmitState, effectId) == 0x0A);
STATIC_ASSERT(offsetof(FxEmitState, altEffectId) == 0x0C);
STATIC_ASSERT(offsetof(FxEmitState, emitCount) == 0x0E);
STATIC_ASSERT(offsetof(FxEmitState, startDelay) == 0x12);
STATIC_ASSERT(offsetof(FxEmitState, enableBit) == 0x14);
STATIC_ASSERT(offsetof(FxEmitState, stopBit) == 0x16);
STATIC_ASSERT(offsetof(FxEmitState, suppressed) == 0x18);
STATIC_ASSERT(offsetof(FxEmitState, sfxTimer) == 0x1A);
STATIC_ASSERT(offsetof(FxEmitState, seqToggle) == 0x1C);
STATIC_ASSERT(offsetof(FxEmitObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(FxEmitObject, state) == 0xB8);
STATIC_ASSERT(offsetof(FxEmitObject, seqCallback) == 0xBC);
STATIC_ASSERT(offsetof(FxEmitObject, emitCooldown) == 0xF4);

void fxemit_emitEffect(FxEmitObject* obj);
int FxEmit_SeqFn(FxEmitObject* obj, int unused, ObjAnimUpdateState* animUpdate);
int FxEmit_getExtraSize(void);
int FxEmit_getObjectTypeId(void);
void FxEmit_free(FxEmitObject* obj);
void FxEmit_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void FxEmit_hitDetect(void);
void FxEmit_update(FxEmitObject* obj);
void FxEmit_init(FxEmitObject* obj, FxEmitPlacement* setup);
void FxEmit_release(void);
void FxEmit_initialise(void);

#endif /* MAIN_DLL_CF_CFTREASSHARPY_H_ */
