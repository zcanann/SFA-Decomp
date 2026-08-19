#ifndef DLLS_OBJECTS_429_SH_THORNTAI_H_
#define DLLS_OBJECTS_429_SH_THORNTAI_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "main/objprint_character_api.h"
#include "game/objects/object_setup.h"
#include "main/dll/curves_collision_state.h"

typedef struct SHthorntailPlacement {
    union {
        ObjPlacement base;
        struct {
            u8 unknown00[0x04];
            f32 unknown04;
            Vec homePosition;
            s32 configToken;
        };
    };
    u8 controlMode;
    u8 initialFacing;
    u8 impactSfxVariant;
    u8 leashRadius;
    u16 scale;
} SHthorntailPlacement;

typedef struct SHthorntailState {
    u8 unknown00[0x04];
    f32 dustEffectTimer;
    u8 unknown08[0xD4 - 0x08];
    u8 dustEffectFlags;
    u8 unknownD5[0x611 - 0xD5];
    u8 movementControlFlags;
    u8 unknown612[0x624 - 0x612];
    s8 behaviorState;
    u8 behaviorFlags;
    u8 locomotionMode;
    u8 tailSwingState;
    f32 tailSwingTimer;
    u8* impactSfxTable;
    f32 idleTimer;
    f32 comboTimer;
    f32 effectTimer;
    s16 storedFacingAngle;
    s8 comboRepeatCount;
    u8 freezeFrameCounter;
    u8 hitReactState;
    u8 unknown641[0x644 - 0x641];
    union {
        CurvesCollisionState pathState;
        u8 moveScratch[sizeof(CurvesCollisionState)];
        struct {
            u8 unknownPathStart[offsetof(CurvesCollisionState, tiltPitch)];
            s16 moveControlPitch;
            s16 moveControlRoll;
            u8 unknownPathTiltToSubtype[offsetof(CurvesCollisionState, subtype) -
                                        (offsetof(CurvesCollisionState, tiltRoll) + sizeof(s16))];
            u8 activeMoveValid;
        };
    };
    u8 hitReactScratch[0x8B0 - 0x8AC];
    CharacterEyeAnimState eyeAnimState;
    u8 pad8D8[0x8];
    Vec renderPathPoints[4];
    f32 proximityAlertState;
} SHthorntailState;

#define SHTHORNTAIL_DUST_FLAG_BURST_READY 0x02
#define SHTHORNTAIL_DUST_FLAG_ACTIVE      0x04
#define SHTHORNTAIL_OBJECT_GROUP          0x4D

STATIC_ASSERT(offsetof(SHthorntailPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(SHthorntailPlacement, unknown04) == 0x04);
STATIC_ASSERT(offsetof(SHthorntailPlacement, homePosition) == 0x08);
STATIC_ASSERT(offsetof(SHthorntailPlacement, configToken) == 0x14);
STATIC_ASSERT(offsetof(SHthorntailPlacement, controlMode) == 0x18);
STATIC_ASSERT(offsetof(SHthorntailPlacement, initialFacing) == 0x19);
STATIC_ASSERT(offsetof(SHthorntailPlacement, impactSfxVariant) == 0x1A);
STATIC_ASSERT(offsetof(SHthorntailPlacement, leashRadius) == 0x1B);
STATIC_ASSERT(offsetof(SHthorntailPlacement, scale) == 0x1C);

STATIC_ASSERT(offsetof(SHthorntailState, dustEffectTimer) == 0x04);
STATIC_ASSERT(offsetof(SHthorntailState, dustEffectFlags) == 0xD4);
STATIC_ASSERT(offsetof(SHthorntailState, movementControlFlags) == 0x611);
STATIC_ASSERT(offsetof(SHthorntailState, behaviorState) == 0x624);
STATIC_ASSERT(offsetof(SHthorntailState, behaviorFlags) == 0x625);
STATIC_ASSERT(offsetof(SHthorntailState, locomotionMode) == 0x626);
STATIC_ASSERT(offsetof(SHthorntailState, tailSwingState) == 0x627);
STATIC_ASSERT(offsetof(SHthorntailState, tailSwingTimer) == 0x628);
STATIC_ASSERT(offsetof(SHthorntailState, impactSfxTable) == 0x62C);
STATIC_ASSERT(offsetof(SHthorntailState, idleTimer) == 0x630);
STATIC_ASSERT(offsetof(SHthorntailState, comboTimer) == 0x634);
STATIC_ASSERT(offsetof(SHthorntailState, effectTimer) == 0x638);
STATIC_ASSERT(offsetof(SHthorntailState, storedFacingAngle) == 0x63C);
STATIC_ASSERT(offsetof(SHthorntailState, comboRepeatCount) == 0x63E);
STATIC_ASSERT(offsetof(SHthorntailState, freezeFrameCounter) == 0x63F);
STATIC_ASSERT(offsetof(SHthorntailState, hitReactState) == 0x640);
STATIC_ASSERT(offsetof(SHthorntailState, moveScratch) == 0x644);
STATIC_ASSERT(offsetof(SHthorntailState, moveControlPitch) == 0x7DC);
STATIC_ASSERT(offsetof(SHthorntailState, moveControlRoll) == 0x7DE);
STATIC_ASSERT(offsetof(SHthorntailState, activeMoveValid) == 0x89F);
STATIC_ASSERT(offsetof(SHthorntailState, hitReactScratch) == 0x8AC);
STATIC_ASSERT(offsetof(SHthorntailState, eyeAnimState) == 0x8B0);
STATIC_ASSERT(offsetof(SHthorntailState, renderPathPoints) == 0x8E0);
STATIC_ASSERT(offsetof(SHthorntailState, proximityAlertState) == 0x910);
STATIC_ASSERT(sizeof(SHthorntailState) == 0x914);

int SHthorntail_getExtraSize(void);
void SHthorntail_free(GameObject* obj);
void SHthorntail_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
void SHthorntail_update(GameObject* obj);
void SHthorntail_init(GameObject* obj, const SHthorntailPlacement* placement);

extern ObjectDescriptor gSH_thorntailObjDescriptor;

#endif /* DLLS_OBJECTS_429_SH_THORNTAI_H_ */
