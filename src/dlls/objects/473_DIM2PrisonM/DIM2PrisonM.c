/*
 * DIM2PrisonM (DLL 0x1D9) - imprisoned mammoth encounter for Snowhorn Wastes 2.
 * It drives the mammoth's idle and interaction states, eye animation, hit
 * reactions, sequence position override, and the EarthWarrior tail-chain hook.
 */
#include "dlls/objects/473_DIM2PrisonM.h"
#include "dlls/objects/599_DR_EarthWar.h"

#include "dolphin/pad.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/savegame_object_api.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/model.h"
#include "main/objHitReact.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/object_render.h"
#include "main/pad_api.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/objprint_character_api.h"

#define DIM2_PRISON_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT 0x08
#define DIM2_PRISON_MAMMOTH_VARIANT_ZERO_GAME_BIT     0x224

typedef int (*Dim2PrisonMammothStateHandler)(GameObject* obj, Dim2PrisonMammothState* state);
typedef int (*Dim2PrisonMammothDefaultStateHandler)(void);


Dim2PrisonMammothStateHandler gDim2PrisonMammothStateHandlers[4];
Dim2PrisonMammothDefaultStateHandler gDim2PrisonMammothDefaultStateHandler[2];
u8 gPrisonMammothStateFlagsTable[4] = {DIM2_PRISON_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT, 0, 0, 0};
s16 gPrisonMammothMoveIdTable[2] = {0x103, 0xB};
f32 gPrisonMammothMoveSpeedTable[2] = {0.0031f, 0.005f};

extern ObjHitReactEntry gPrisonMammothHitReactEntry[];

int dim2prisonmammoth_defaultStateHandler(void) {
    return 0;
}

int dim2prisonmammoth_stateHandler03(GameObject* obj, Dim2PrisonMammothState* state) {
    f32 fz = 0.0f;

    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    state->baddie.flags0 |= 0x200000;
    if (state->baddie.moveJustStartedA != 0) {
        int k = randomGetRange(0, 1);

        state->baddie.moveSpeed = gPrisonMammothMoveSpeedTable[k];
        ObjAnim_SetCurrentMove(obj, gPrisonMammothMoveIdTable[k], 0.0f, 0);
    }
    if (state->baddie.moveDone != 0) {
        return -1;
    }

    return 0;
}

int dim2prisonmammoth_stateHandler02(GameObject* obj, Dim2PrisonMammothState* state) {
    Dim2PrisonMammothState* objectState = obj->extra;
    f32 fz = 0.0f;

    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    state->baddie.flags0 |= 0x200000;
    state->baddie.moveSpeed = 0.005f;
    if (obj->anim.currentMove != 0) {
        ObjAnim_SetCurrentMove(obj, 0, fz, 0);
    }
    objectState->stateTimer = randomGetRange(0x4B0, 0x960);
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        buttonDisable(0, PAD_BUTTON_A);
    }

    return 0;
}

int dim2prisonmammoth_stateHandler01(GameObject* obj, Dim2PrisonMammothState* state) {
    Dim2PrisonMammothState* objectState = obj->extra;
    f32 fz = 0.0f;

    state->baddie.animSpeedC = fz;
    state->baddie.animSpeedB = fz;
    state->baddie.animSpeedA = fz;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = fz;
    obj->anim.velocityZ = fz;
    state->baddie.flags0 |= 0x200000;
    if (state->baddie.moveJustStartedA != 0) {
        state->baddie.moveSpeed = 0.005f;
        if (obj->anim.currentMove != 5) {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
        }
        objectState->stateTimer = randomGetRange(0x4B0, 0x960);
    }
    if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
        mainSetBits(GAMEBIT_DIM_FoundBelinaTe, 1);
        buttonDisable(0, PAD_BUTTON_A);
    }
    if (RandomTimer_UpdateRangeTrigger(&objectState->callTimer, 4.0f, 8.0f) != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_hightop_call1);
    }

    return 0;
}

int dim2prisonmammoth_stateHandler00(GameObject* obj) {
    const Dim2PrisonMammothPlacement* placement = (const Dim2PrisonMammothPlacement*)obj->anim.placementData;

    switch (placement->spawnVariant) {
    case 0:
        if (mainGetBit(DIM2_PRISON_MAMMOTH_VARIANT_ZERO_GAME_BIT) != 0) {
            return 3;
        }
        return 2;
    case 1:
        if (mainGetBit(GAMEBIT_DIM_ReachedBottom) != 0) {
            return 3;
        }
        return 3;
    default:
        return 0;
    }
}

int dim2prisonmammoth_SeqFn(GameObject* obj, int unusedState, ObjSeqState* animUpdate) {
    MatrixTransform transform;
    f32 matrix[16];
    Dim2PrisonMammothState* state;

    animUpdate->movementState = 0;
    animUpdate->flags = animUpdate->savedFlags;
    state = obj->extra;
    (*gPlayerInterface)->setState(obj, state, 2);

    transform.x = obj->anim.localPosX;
    transform.y = obj->anim.localPosY;
    transform.z = obj->anim.localPosZ;
    transform.rotX = obj->anim.rotX;
    transform.rotY = obj->anim.rotY;
    transform.rotZ = obj->anim.rotZ;
    transform.scale = obj->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, &transform);

    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f, &obj->anim.modelState->overrideWorldPosX,
                          &obj->anim.modelState->overrideWorldPosY, &obj->anim.modelState->overrideWorldPosZ);

    return 0;
}

int dim2prisonmammoth_getExtraSize(void) {
    return sizeof(Dim2PrisonMammothState);
}

int dim2prisonmammoth_getObjectTypeId(void) {
    return 0;
}

void dim2prisonmammoth_free(void) {
}

void dim2prisonmammoth_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                              s8 visible) {
    if (visible != 0) {
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
    }
}

void dim2prisonmammoth_hitDetect(void) {
}

void dim2prisonmammoth_update(GameObject* obj) {
    MatrixTransform transform;
    f32 matrix[16];
    Dim2PrisonMammothState* state = obj->extra;

    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
    if ((gPrisonMammothStateFlagsTable[state->baddie.controlMode] & DIM2_PRISON_MAMMOTH_STATE_FLAG_SKIP_HIT_REACT) ==
        0) {
        state->hitReactState = ObjHitReact_Update(obj, gPrisonMammothHitReactEntry, 1, state->hitReactState,
                                                  &state->hitReactStepScale);
        if (state->hitReactState != 0) {
            characterHeadLookRelax(obj, &state->eyeAnim);
            characterDoEyeAnims(obj, &state->eyeAnim);
            return;
        }
    }
    characterDoEyeAnims(obj, &state->eyeAnim);
    transform.x = obj->anim.localPosX;
    transform.y = obj->anim.localPosY;
    transform.z = obj->anim.localPosZ;
    transform.rotX = obj->anim.rotX;
    transform.rotY = obj->anim.rotY;
    transform.rotZ = obj->anim.rotZ;
    transform.scale = obj->anim.rootMotionScale;
    setMatrixFromObjectPos(matrix, &transform);
    Matrix_TransformPoint(matrix, 0.0f, 0.0f, 0.0f, &obj->anim.modelState->overrideWorldPosX,
                          &obj->anim.modelState->overrideWorldPosY, &obj->anim.modelState->overrideWorldPosZ);
    state->baddie.hitPoints = 0;
    state->baddie.flags0 &= ~0x8000;
    {
        f32 fz = 0.0f;

        state->baddie.moveInputX = fz;
        state->baddie.moveInputZ = fz;
    }
    state->baddie.pressedButtons = 0;
    state->baddie.heldButtons = 0;
    state->baddie.cameraYaw = 0;
    state->baddie.flags0 |= 0x400000;
    (*gPlayerInterface)
        ->update(obj, state, timeDelta, timeDelta, gDim2PrisonMammothStateHandlers,
                 gDim2PrisonMammothDefaultStateHandler);
    saveGame_saveObjectPos(obj);
}

void dim2prisonmammoth_init(GameObject* obj, const Dim2PrisonMammothPlacement* placement) {
    Dim2PrisonMammothState* state;

    obj->anim.rotX = placement->rotationXByte << 8;
    obj->animEventCallback = dim2prisonmammoth_SeqFn;
    state = obj->extra;
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_UNREAD_0010 | OBJ_MODEL_STATE_UNREAD_0200 | OBJ_MODEL_STATE_UNREAD_0800;
        obj->anim.modelState->flags |= OBJ_MODEL_STATE_UNREAD_8000 | OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE;
    }
    (*gPlayerInterface)->init(obj, state, 4, 1);
    state->baddie.physicsActive = 0;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
}

void dim2prisonmammoth_release(void) {
}

void dim2prisonmammoth_initialise(void) {
    gDim2PrisonMammothStateHandlers[0] = (Dim2PrisonMammothStateHandler)dim2prisonmammoth_stateHandler00;
    gDim2PrisonMammothStateHandlers[1] = dim2prisonmammoth_stateHandler01;
    gDim2PrisonMammothStateHandlers[2] = dim2prisonmammoth_stateHandler02;
    gDim2PrisonMammothStateHandlers[3] = dim2prisonmammoth_stateHandler03;
    gDim2PrisonMammothDefaultStateHandler[0] = dim2prisonmammoth_defaultStateHandler;
}

/*
 * The only proven consumer is DR_EarthWarrior. This callback reads that
 * object's 0x14FC-byte state, not this DLL's 0x604-byte allocation.
 */
void dim2prisonmammoth_updateModelChain(GameObject* obj, ObjModel* model) {
    EarthWarriorState* state = (EarthWarriorState*)obj->extra;

    ObjModelChain_Update(model, model->file, state->sub.modelChain, NULL);
}

ObjHitReactEntry gPrisonMammothHitReactEntry[] = {
    {730, 885, 48, -1, 0, {0, 0, 0}, 0.012f, {0, 0, 0, 0}},
};

ObjectDescriptor10WithPadding gDIM2PrisonMammothObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        dim2prisonmammoth_initialise,
        dim2prisonmammoth_release,
        0,
        (ObjectDescriptorCallback)dim2prisonmammoth_init,
        (ObjectDescriptorCallback)dim2prisonmammoth_update,
        dim2prisonmammoth_hitDetect,
        (ObjectDescriptorCallback)dim2prisonmammoth_render,
        dim2prisonmammoth_free,
        (ObjectDescriptorCallback)dim2prisonmammoth_getObjectTypeId,
        dim2prisonmammoth_getExtraSize,
    },
    0,
};
