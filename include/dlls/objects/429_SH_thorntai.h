#ifndef DLLS_OBJECTS_429_SH_THORNTAI_H_
#define DLLS_OBJECTS_429_SH_THORNTAI_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/objprint_character_api.h"
#include "main/dll/curves_collision_state.h"
#include "main/dll/dll_002E_moveLib.h"

typedef struct SHthorntailPlacement {
    union {
        ObjPlacement base;
        struct {
            u8 pad00[0x08];
            Vec homePosition;
            s32 ident;
        };
    };
    u8 variant;
    u8 initialFacing;
    u8 talkSeqVariant;
    u8 leashRadius;
    u16 scale;
} SHthorntailPlacement;

typedef struct SHthorntailState {
    MoveLibState moveLib;
    s8 behaviorState;
    u8 behaviorFlags;
    u8 mapAct;
    u8 snoreState;
    f32 snoreTimer;
    u8* talkSeqs;
    f32 idleTimer;
    f32 grazeWaitTimer;
    f32 sleepEffectTimer;
    s16 storedFacingAngle;
    s8 grazeRepeatCount;
    u8 freezeFrameCounter;
    u8 hitReactState;
    u8 pad641[0x3];
    CurvesCollisionState pathState;
    f32 hitReactStepScale;
    CharacterEyeAnimState eyeAnimState;
    u8 pad8D8[0x8];
    Vec renderPathPoints[4];
    f32 proximityAlertTimer;
} SHthorntailState;

#define SHTHORNTAIL_OBJECT_GROUP 0x4D

STATIC_ASSERT(offsetof(SHthorntailPlacement, homePosition) == 0x08);
STATIC_ASSERT(offsetof(SHthorntailPlacement, ident) == 0x14);
STATIC_ASSERT(offsetof(SHthorntailPlacement, variant) == 0x18);
STATIC_ASSERT(offsetof(SHthorntailPlacement, scale) == 0x1C);

STATIC_ASSERT(offsetof(SHthorntailState, behaviorState) == 0x624);
STATIC_ASSERT(offsetof(SHthorntailState, snoreTimer) == 0x628);
STATIC_ASSERT(offsetof(SHthorntailState, talkSeqs) == 0x62C);
STATIC_ASSERT(offsetof(SHthorntailState, storedFacingAngle) == 0x63C);
STATIC_ASSERT(offsetof(SHthorntailState, hitReactState) == 0x640);
STATIC_ASSERT(offsetof(SHthorntailState, pathState) == 0x644);
STATIC_ASSERT(offsetof(SHthorntailState, hitReactStepScale) == 0x8AC);
STATIC_ASSERT(offsetof(SHthorntailState, eyeAnimState) == 0x8B0);
STATIC_ASSERT(offsetof(SHthorntailState, renderPathPoints) == 0x8E0);
STATIC_ASSERT(offsetof(SHthorntailState, proximityAlertTimer) == 0x910);
STATIC_ASSERT(sizeof(SHthorntailState) == 0x914);

int SHthorntail_getExtraSize(void);
void SHthorntail_free(GameObject* obj);
void SHthorntail_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void SHthorntail_update(GameObject* obj);
void SHthorntail_init(GameObject* obj, const SHthorntailPlacement* placement);

extern ObjectDescriptor gSH_thorntailObjDescriptor;

#endif /* DLLS_OBJECTS_429_SH_THORNTAI_H_ */
