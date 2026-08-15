/*
 * Curve-following light-action emitter with optional lifetime, GameBit gate,
 * per-axis spin, free movement, and falling-velocity damping.
 */
#include "dlls/objects/301_LFXEmitter.h"

#include "main/dll/rom_curve_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mldf_fileid.h"
#include "main/mm.h"
#include "sys/objects.h"
#include "main/curve.h"
#include "main/asset_load.h"
#include "main/objtype.h"
#include "sys/objects/lifecycle.h"

#define LFXEMITTER_OBJECT_GROUP        0x1C
#define LFXEMITTER_LIGHT_ACTION_HEAP   0x12
#define LFXEMITTER_CACHE_INDEX_INVALID 10000

#define LFXEMITTER_FALL_SPEED_LIMIT   -15.0f
#define LFXEMITTER_FALL_ACCELERATION  -0.01f
#define LFXEMITTER_ROOT_MOTION_SCALE  2.0f
#define LFXEMITTER_CURVE_SPEED_SCALE  10.0f
#define LFXEMITTER_CURVE_SEARCH_RANGE 1000.0f

/*
 * LACTIONS.bin contains fixed 0x28-byte rows. Populated retail rows carry
 * their one-based row index at +0x0E; the emitter uses it as its cache key.
 */
struct LFXEmitterLightAction {
    u16 unk00;
    u16 unk02;
    s16 unk04;
    s16 unk06;
    s16 unk08;
    s16 unk0A;
    s16 unk0C;
    u16 oneBasedIndex;
    u8 unk10;
    u8 unk11;
    u8 unk12;
    u8 unk13;
    u8 unk14;
    u8 unk15;
    u8 unk16;
    u8 unk17;
    u8 unk18;
    u8 unk19;
    u8 unk1A;
    u8 unk1B;
    u8 unk1C;
    u8 unk1D;
    u8 unk1E;
    u8 unk1F;
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 unk24;
    u8 unk25;
    u8 unk26;
    u8 unk27;
};

STATIC_ASSERT(offsetof(LFXEmitterLightAction, oneBasedIndex) == 0x0E);
STATIC_ASSERT(offsetof(LFXEmitterLightAction, unk10) == 0x10);
STATIC_ASSERT(offsetof(LFXEmitterLightAction, unk12) == 0x12);
STATIC_ASSERT(offsetof(LFXEmitterLightAction, unk1B) == 0x1B);
STATIC_ASSERT(offsetof(LFXEmitterLightAction, unk27) == 0x27);
STATIC_ASSERT(sizeof(LFXEmitterLightAction) == 0x28);

LFXEmitterLightAction gLFXEmitterLightActionCache;

int LFXEmitter_isLightActionLoaded(GameObject* obj) {
    LFXEmitterState* state = obj->extra;
    return state->lightAction != NULL;
}

int LFXEmitter_func0A(void) {
    return -1;
}

void LFXEmitter_copyLightAction(const LFXEmitterLightAction* source, LFXEmitterLightAction* destination) {
    destination->unk00 = source->unk00;
    destination->unk02 = source->unk02;
    destination->unk04 = source->unk04;
    destination->unk06 = source->unk06;
    destination->unk08 = source->unk08;
    destination->unk0A = source->unk0A;
    destination->unk0C = source->unk0C;
    destination->oneBasedIndex = source->oneBasedIndex;
    destination->unk12 = source->unk12;
    destination->unk13 = source->unk13;
    destination->unk1B = source->unk1B;
    destination->unk1C = source->unk1C;
    destination->unk1D = source->unk1D;
    destination->unk1E = source->unk1E;
    destination->unk1F = source->unk1F;
    destination->unk20 = source->unk20;
    destination->unk21 = source->unk21;
    destination->unk22 = source->unk22;
    destination->unk15 = source->unk15;
    destination->unk23 = source->unk23;
    destination->unk16 = source->unk16;
    destination->unk24 = source->unk24;
    destination->unk17 = source->unk17;
    destination->unk25 = source->unk25;
    destination->unk18 = source->unk18;
    destination->unk26 = source->unk26;
    destination->unk19 = source->unk19;
    destination->unk27 = source->unk27;
    destination->unk1A = source->unk1A;

    /*
     * Retail also copies byte +0x28. The cache is exactly 0x28 bytes, so this
     * intentionally preserves the original one-byte overrun into the next
     * BSS object instead of disguising it as part of this allocation.
     */
    ((u8*)destination)[sizeof(*destination)] = ((const u8*)source)[sizeof(*source)];
}

int LFXEmitter_getExtraSize(void) {
    return sizeof(LFXEmitterState);
}

int LFXEmitter_getObjectTypeId(void) {
    return 0;
}

void LFXEmitter_free(GameObject* obj) {
    LFXEmitterState* state = obj->extra;
    LFXEmitterLightAction* lightAction = state->lightAction;

    if (lightAction != NULL) {
        mm_free(lightAction);
    }
    objFreeObjectType(obj, LFXEMITTER_OBJECT_GROUP);
}

void LFXEmitter_render(void) {
}

void LFXEmitter_hitDetect(void) {
}

void LFXEmitter_update(GameObject* obj) {
    LFXEmitterState* state;
    GameObject* player;

    state = obj->extra;
    player = Obj_GetPlayerObject();

    obj->anim.rotX += state->spinYaw;
    obj->anim.rotZ += state->spinRoll;
    obj->anim.rotY += state->spinPitch;

    if ((state->flags & LFXEMITTER_FLAG_FOLLOW_CURVE) != 0) {
        if ((Curve_AdvanceAlongPath(&state->curve.curve, state->curveSpeed) != 0) || (state->curve.atSegmentEnd != 0)) {
            (*gRomCurveInterface)->goNextPoint(&state->curve);
        }
        obj->anim.localPosX = state->curve.posX;
        obj->anim.localPosY = state->curve.posY;
        obj->anim.localPosZ = state->curve.posZ;
    } else {
        obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->anim.localPosX;
        obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->anim.localPosY;
        obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->anim.localPosZ;
        if (((state->flags & LFXEMITTER_FLAG_DAMP_Y_VELOCITY) != 0) &&
            (obj->anim.velocityY > LFXEMITTER_FALL_SPEED_LIMIT)) {
            obj->anim.velocityY = LFXEMITTER_FALL_ACCELERATION * timeDelta + obj->anim.velocityY;
        }
    }

    if ((player != NULL) &&
        ((state->enableGameBit == LFXEMITTER_GAME_BIT_NONE) || (mainGetBit(state->enableGameBit) != 0))) {
        if (state->lifeTimerActive != 0) {
            state->lifeTimer -= framesThisStep;
            if (state->lifeTimer <= 0) {
                Obj_FreeObject(obj);
                return;
            }
        }
        if (state->lightActionLoaded == 0) {
            if ((state != NULL) && (state->actionIndex == (gLFXEmitterLightActionCache.oneBasedIndex - 1))) {
                state->lightAction = mmAlloc(sizeof(LFXEmitterLightAction), LFXEMITTER_LIGHT_ACTION_HEAP, 0);
                if (state->lightAction != NULL) {
                    LFXEmitter_copyLightAction(&gLFXEmitterLightActionCache, state->lightAction);
                }
            } else {
                state->lightAction = mmAlloc(sizeof(LFXEmitterLightAction), LFXEMITTER_LIGHT_ACTION_HEAP, 0);
                getTabEntry(state->lightAction, MLDF_FILEID_LACTIONS_BIN,
                            state->actionIndex * sizeof(LFXEmitterLightAction), sizeof(LFXEmitterLightAction));
                if (state->lightAction != NULL) {
                    LFXEmitter_copyLightAction(state->lightAction, &gLFXEmitterLightActionCache);
                }
            }
            state->lightActionLoaded = 1;
        }
    }
}

void LFXEmitter_init(GameObject* obj, LFXEmitterPlacement* placement) {
    LFXEmitterState* state;
    int curveFlags;

    state = obj->extra;
    curveFlags = 0x21;
    obj->anim.rootMotionScale = LFXEMITTER_ROOT_MOTION_SCALE * obj->anim.modelInstance->rootMotionScaleBase;

    state->actionIndex = placement->actionIndex;
    state->lifeTimer = placement->lifeTimer;
    state->unk114 = -2;
    state->enableGameBit = placement->enableGameBit;
    state->spinRoll = placement->spinRoll;
    state->spinPitch = placement->spinPitch;
    state->spinYaw = placement->spinYaw;
    obj->anim.localPosX = placement->base.posX;
    obj->anim.localPosY = placement->base.posY;
    obj->anim.localPosZ = placement->base.posZ;

    if (state->lifeTimer != 0) {
        state->lifeTimerActive = 1;
    } else {
        state->lifeTimerActive = 0;
    }

    if (placement->followCurve != 0) {
        state->flags |= LFXEMITTER_FLAG_FOLLOW_CURVE;
        state->curveSpeed = placement->curveSpeed / LFXEMITTER_CURVE_SPEED_SCALE;
        (*gRomCurveInterface)
            ->initCurve(&state->curve, obj, LFXEMITTER_CURVE_SEARCH_RANGE, &curveFlags, LFXEMITTER_GAME_BIT_NONE);
    }
    objAddObjectType(obj, LFXEMITTER_OBJECT_GROUP);
}

void LFXEmitter_release(void) {
}

void LFXEmitter_initialise(void) {
    gLFXEmitterLightActionCache.oneBasedIndex = LFXEMITTER_CACHE_INDEX_INVALID;
}

ObjectDescriptor12 gLFXEmitterObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)LFXEmitter_initialise,
    (ObjectDescriptorCallback)LFXEmitter_release,
    0,
    (ObjectDescriptorCallback)LFXEmitter_init,
    (ObjectDescriptorCallback)LFXEmitter_update,
    (ObjectDescriptorCallback)LFXEmitter_hitDetect,
    (ObjectDescriptorCallback)LFXEmitter_render,
    (ObjectDescriptorCallback)LFXEmitter_free,
    (ObjectDescriptorCallback)LFXEmitter_getObjectTypeId,
    LFXEmitter_getExtraSize,
    (ObjectDescriptorCallback)LFXEmitter_func0A,
    (ObjectDescriptorCallback)LFXEmitter_isLightActionLoaded,
};
