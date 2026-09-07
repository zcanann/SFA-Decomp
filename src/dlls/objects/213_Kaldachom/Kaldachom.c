/*
 * Kaldachom object (DLL slot 213).
 *
 * Controls a door-mounted baddie through two state-handler tables, including
 * its pull-up attack, mouth projectiles, hit reactions, and dust effects.
 */
#include "dlls/objects/213_Kaldachom.h"
#include "dlls/objects/214_KaldachomMe.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/objfx_api.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/player_control_interface.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/audio/sfx_play_api.h"
#include "main/dll/player_state_api.h"
#include "main/gamebits_api.h"
#include "main/obj_path.h"
#include "main/objtype.h"

typedef struct KaldachomCombatParams {
    u32 unk00;
    u32 unk04;
    u32 unk08;
    u32 unk0C;
} KaldachomCombatParams;

typedef struct KaldachomCombatStack {
    f32 dx;
    f32 dy;
    f32 dz;
    KaldachomCombatParams params;
} KaldachomCombatStack;

STATIC_ASSERT(sizeof(KaldachomCombatParams) == 0x10);
STATIC_ASSERT(offsetof(KaldachomCombatStack, params) == 0xC);
STATIC_ASSERT(sizeof(KaldachomCombatStack) == 0x1C);

#define KALDACHOM_CONTROL_MODE_PULLUP 2
#define KALDACHOM_CONTROL_MODE_RETURN 6

#define KALDACHOM_SOUND_FLAG_PULLUP_BURST 0x1
#define KALDACHOM_SOUND_FLAG_DOOR_CREAK   0x2

#define KALDACHOM_AGGRO_CHANCE_RANGE 0x63

#define KALDACHOM_EVENT_MOUTH_LINK       0x1000
#define KALDACHOM_EVENT_UPPER_PROJECTILE 0x800
#define KALDACHOM_EVENT_ATTACK_FX        0x400
#define KALDACHOM_EVENT_CLIMB_FX         0x80
#define KALDACHOM_EVENT_LOWER_PROJECTILE 0x40

#define KALDACHOM_OBJECT_GROUP                    3
#define KALDACHOM_OBJECT_TYPE_ID                  0x49

#define KALDACHOM_CHILD_OBJ_DUST             0x55e
#define KALDACHOM_CHILD_OBJ_MOUTH_PROJECTILE 0x51b

#define KALDACHOM_PARTFX_DUST   0x717
#define KALDACHOM_PARTFX_CLIMB  0x711
#define KALDACHOM_PARTFX_ATTACK 0x710

#define KALDACHOM_EFFECT_RESOURCE_ID 0x5a


const KaldachomCombatParams gKaldachomCombatParams = {8, 255, 255, 120};
int lbl_803DDA9C;
f32 gKaldachomMouthSpawnScratch;
f32 gKaldachomDustSpawnScratch;
StaffCollisionInterface** gKaldachomEffectResource;
PartFxSpawnParams gKaldachomHitLightWork;
KaldachomStateHandler gKaldachomStateHandlersB[6];

s16 gKaldachomMoves[6] = {0, 0, 1, 1, 2, 0};

f32 gKaldachomMoveSpeeds[5] = {0.004f, 0.006f, 0.01f, 0.01f, 0.01f};


int kaldachom_stateHandlerB05(GameObject* obj, GroundBaddieState* state) {
    KaldachomState* objectState;
    KaldachomControl* control;
    KaldachomPlacement* placement;

    objectState = obj->extra;
    control = ((KaldachomControl*)objectState->ground.control);
    if (state->baddie.controlMode == KALDACHOM_CONTROL_MODE_PULLUP) {
        control->pullupSfxTimer -= timeDelta;
        if (control->pullupSfxTimer <= 0.0f) {
            state->baddie.moveDone = 1;
        }
    }
    if (state->baddie.moveDone != 0 || state->baddie.moveJustStartedB != 0) {
        if ((*gBaddieControlInterface)->shouldDropTarget(obj, state, (f32)(u32)objectState->ground.aggroRange, 1) != 0) {
            return 5;
        }
        placement = (KaldachomPlacement*)obj->anim.placementData;
        if (randomGetRange(0, KALDACHOM_AGGRO_CHANCE_RANGE) < (int)placement->aggroChance) {
            (*gPlayerInterface)->setState(obj, state, 3);
        } else {
            control->pullupSfxTimer = randomGetRange(300, 600);
            (*gPlayerInterface)->setState(obj, state, 2);
        }
    }
    return 0;
}

int kaldachom_stateHandlerB04(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, state, 1);
    }
    return 0;
}

int kaldachom_stateHandlerB03(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        KaldachomState* objectState = obj->extra;
        objectState->ground.subMode = 0;
        mainSetBits(objectState->ground.gameBitB, 0);
        mainSetBits(objectState->ground.gameBitA, 1);
    }
    return 0;
}

int kaldachom_stateHandlerB02(GameObject* obj, GroundBaddieState* state) {
    KaldachomState* objectState = obj->extra;

    if ((s32)state->baddie.moveJustStartedB != 0) {
        ((KaldachomControl*)objectState->ground.control)->soundFlags = 0;
        (*gPlayerInterface)->setState(obj, state, 7);
        ObjHits_DisableObject(obj);
        obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        objectState->ground.flags400 |= 0x20;
        objectState->ground.glowAlpha = 1.0f;
        objectState->ground.glowRate = 0.01f;
    } else if ((s32)state->baddie.moveDone != 0) {
        if (obj->anim.placementData == NULL) {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int kaldachom_stateHandlerB01(GameObject* obj, GroundBaddieState* state) {
    KaldachomControl* control = ((KaldachomControl*)((KaldachomState*)obj->extra)->ground.control);
    if (state->baddie.controlMode == KALDACHOM_CONTROL_MODE_RETURN) {
        f32 zero;
        f32 timer;
        if (state->baddie.moveJustStartedB != 0) {
            control->returnStateTimer = 300.0f;
        }
        timer = control->returnStateTimer;
        zero = 0.0f;
        if (timer != zero) {
            control->returnStateTimer = timer - timeDelta;
            if (control->returnStateTimer < zero) {
                control->returnStateTimer = zero;
            }
        } else {
            return 6;
        }
    } else {
        if (state->baddie.moveDone != 0) {
            return 6;
        }
    }
    return 0;
}

int kaldachom_stateHandlerB00(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.targetObj != NULL) {
        if (state->baddie.moveJustStartedB != 0) {
            f32 zeroSpeed = 0.0f;
            state->baddie.animSpeedB = zeroSpeed;
            state->baddie.animSpeedA = zeroSpeed;
            (*gPlayerInterface)->setState(obj, state, 0);
        } else if (state->baddie.moveDone != 0) {
            return 6;
        }
    }
    return 0;
}

int kaldachom_stateHandlerA07(GameObject* obj, GroundBaddieState* state) {
    KaldachomState* objectState;
    KaldachomControl* control;

    objectState = obj->extra;
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.008f;
    {
        f32 fz = 0.0f;
        state->baddie.animSpeedA = fz;
        state->baddie.animSpeedB = fz;
        if (state->baddie.moveJustStartedA != '\0') {
            ObjAnim_SetCurrentMove(obj, 5, fz, 0);
            state->baddie.moveDone = 0;
        }
    }
    {
        int eventFlags = state->baddie.eventFlags;
        if ((eventFlags & KALDACHOM_EVENT_MOUTH_LINK) != 0) {
            state->baddie.eventFlags = eventFlags & ~KALDACHOM_EVENT_MOUTH_LINK;
            kaldachomme_setLinkedMouthMode(obj, KALDACHOMME_LINKED_MODE_MOVE_1);
        }
    }
    control = ((KaldachomControl*)objectState->ground.control);
    if ((control->soundFlags & KALDACHOM_SOUND_FLAG_PULLUP_BURST) == 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_mn_impyflap16);
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_277);
        Sfx_PlayFromObject(obj, SFXTRIG_en_rfall5_c);
        control->soundFlags |= KALDACHOM_SOUND_FLAG_PULLUP_BURST;
        {
            GameObject* linkedObj;
            if (objectState->ground.triggerId != 0) {
                linkedObj = (*gBaddieControlInterface)->spawnChild(obj, 6, -1, 0);
            } else {
                linkedObj = NULL;
            }
            if (linkedObj != NULL) {
                f32 fz = 0.0f;
                ((void (*)(GameObject*, f32, f32, f32))linkedObj->anim.dll[0][11])(
                    linkedObj, fz, 1.0f, fz);
            }
        }
    }
    if ((control->soundFlags & KALDACHOM_SOUND_FLAG_DOOR_CREAK) == 0) {
        if (obj->anim.currentMoveProgress > 0.3f) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_iceywindlp16_233);
            control->soundFlags |= KALDACHOM_SOUND_FLAG_DOOR_CREAK;
        }
    }
    obj->anim.alpha = (1.0f - obj->anim.currentMoveProgress) * 255.0f;
    return 0;
}

int kaldachom_stateHandlerA06(GameObject* obj, GroundBaddieState* state) {
    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_277);
    }
    obj->anim.rotX += 546;
    state->baddie.stateTag = 1;
    state->baddie.moveSpeed = 0.015f;
    state->baddie.animSpeedA = 0.0f;
    return 0;
}

int kaldachom_stateHandlerA05(GameObject* obj, GroundBaddieState* state) {
    KaldachomControl* control = ((KaldachomControl*)((KaldachomState*)obj->extra)->ground.control);

    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, gKaldachomMoves[4], 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        control->climbFxIndex = 4;
    }
    state->baddie.moveSpeed = gKaldachomMoveSpeeds[control->climbFxIndex];
    state->baddie.stateTag = 1;
    return 0;
}

int kaldachom_stateHandlerA04(GameObject* obj, GroundBaddieState* state) {
    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 3, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        Sfx_PlayFromObject(obj, SFXTRIG_dn_boar1_c_277);
    }
    state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.015f;
    state->baddie.animSpeedA = 0.0f;
    return 0;
}

int kaldachom_stateHandlerA03(GameObject* obj, GroundBaddieState* state) {
    if ((s32)state->baddie.moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, randomGetRange(6, 7), 0.0f, 0);
            state->baddie.moveDone = 0;
        }
    }
    state->baddie.moveSpeed = 0.02f;
    state->baddie.stateTag = 1;
    return 0;
}

int kaldachom_stateHandlerA02(GameObject* obj, GroundBaddieState* state) {
    KaldachomControl* control = ((KaldachomControl*)((KaldachomState*)obj->extra)->ground.control);

    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, gKaldachomMoves[randomGetRange(0, 4)], 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        ObjHits_EnableObject(obj);
        control->climbFxIndex = 4;
    }
    state->baddie.moveSpeed = gKaldachomMoveSpeeds[control->climbFxIndex];
    state->baddie.stateTag = 1;
    return 0;
}

int kaldachom_stateHandlerA01(GameObject* obj, GroundBaddieState* state) {
    KaldachomState* objectState = obj->extra;

    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 5, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        ObjHits_DisableObject(obj);
        state->baddie.moveSpeed = 0.01f;
        state->baddie.animSpeedA = 0.0f;
    } else if ((s32)state->baddie.moveDone != 0) {
        mainSetBits(objectState->ground.gameBitB, 0);
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        objectState->ground.targetState = 0;
    }
    if ((s32)(state->baddie.eventFlags & KALDACHOM_EVENT_MOUTH_LINK) != 0) {
        state->baddie.eventFlags &= ~KALDACHOM_EVENT_MOUTH_LINK;
        kaldachomme_setLinkedMouthMode(obj, KALDACHOMME_LINKED_MODE_MOVE_1);
    }
    return 0;
}

int kaldachom_stateHandlerA00(GameObject* obj, GroundBaddieState* state) {
    KaldachomState* objectState = obj->extra;

    if ((s32)state->baddie.moveJustStartedA != 0) {
        if ((s32)state->baddie.moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
            state->baddie.moveDone = 0;
        }
        kaldachomme_setLinkedMouthMode(obj, KALDACHOMME_LINKED_MODE_MOVE_0);
        state->baddie.physicsActive = 1;
        mainSetBits(objectState->ground.gameBitB, 1);
        obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
        obj->anim.alpha = 0xff;
        state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.012f + ((f32)(u32)objectState->ground.aggression / 10000.0f);
        ObjHits_EnableObject(obj);
    } else if ((s32)state->baddie.moveDone != 0) {
        objectState->ground.targetState = 1;
    }
    return 0;
}

void kaldachom_spawnDustEffects(GameObject* obj, KaldachomControl* control) {
    u8 loadLocked;
    KaldachomPlacement* placement;
    ObjPlacement* setup;
    GameObject* dustObj;
    int work;

    placement = (KaldachomPlacement*)obj->anim.placementData;
    gKaldachomDustSpawnScratch = 0.5f + (f32)(s32)placement->scale / 15.0f;
    control->hitFlashTimer = 255.0f;
    Sfx_PlayFromObject(obj, SFXTRIG_wp_beamgenlp16_276);
    work = 40;
    do {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, KALDACHOM_PARTFX_DUST, 0, 4, 0xffffffff, &gKaldachomDustSpawnScratch);
        work--;
    } while (work != 0);
    if ((control->spawnedDustObj == NULL) && (loadLocked = Obj_CanSetupObject(), loadLocked != '\0')) {
        setup = Obj_AllocObjectSetup(0x24, KALDACHOM_CHILD_OBJ_DUST);
        setup->posX = obj->anim.localPosX;
        setup->posY = 10.0f + obj->anim.localPosY;
        setup->posZ = obj->anim.localPosZ;
        setup->color[0] = placement->base.color[0];
        setup->color[1] = placement->base.color[1];
        setup->color[2] = placement->base.color[2];
        setup->color[3] = placement->base.color[3];
        dustObj = objSetupObject(setup, 5, 0xffffffff, 0xffffffff, 0);
        control->spawnedDustObj = dustObj;
        control->spawnedDustObj->anim.rootMotionScale = gKaldachomDustSpawnScratch;
    }
}

void kaldachom_spawnMouthProjectile(GameObject* obj, KaldachomState* state, u8 useUpperMouthPoint) {
    KaldachomControl* control;
    KaldachomPlacement* placement;
    ObjPlacement* setup;
    GameObject* projectile;
    f32 yJitter;
    f32 travelTime;
    f32 heightOffset;
    f32 mouthY;
    u8 canSetupObject;

    control = ((KaldachomControl*)state->ground.control);
    placement = (KaldachomPlacement*)obj->anim.placementData;
    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        heightOffset = 0.5f + (f32)(s32)placement->scale / 15.0f;
        setup = Obj_AllocObjectSetup(0x24, KALDACHOM_CHILD_OBJ_MOUTH_PROJECTILE);
        if (useUpperMouthPoint != 0) {
            setup->posX = control->upperMouthPosX;
            setup->posY = control->upperMouthPosY;
            setup->posZ = control->upperMouthPosZ;
        } else {
            setup->posX = control->lowerMouthPosX;
            setup->posY = control->lowerMouthPosY;
            setup->posZ = control->lowerMouthPosZ;
        }
        setup->color[0] = 1;
        setup->color[1] = 4;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        projectile = objSetupObject(setup, 5, 0xffffffff, 0xffffffff, 0);
        if (projectile != NULL) {
            travelTime = 60.0f * (state->ground.baddie.targetDistance / (f32)(u32)state->ground.aggroRange);
            projectile->anim.velocityX = (((GameObject*)state->ground.baddie.targetObj)->anim.localPosX - setup->posX) / travelTime;
            yJitter = (f32)(s32)randomGetRange(-10, 10);
            mouthY = 10.0f * heightOffset + ((GameObject*)state->ground.baddie.targetObj)->anim.localPosY;
            projectile->anim.velocityY = (mouthY + yJitter - setup->posY) / travelTime;
            projectile->anim.velocityZ = (((GameObject*)state->ground.baddie.targetObj)->anim.localPosZ - setup->posZ) / travelTime;
        }
    }
}

void kaldachom_handleAnimEvents(GameObject* obj, KaldachomState* objectState, GroundBaddieState* state) {
    KaldachomControl* control = ((KaldachomControl*)objectState->ground.control);
    int spawnCount;

    gKaldachomMouthSpawnScratch =
        0.5f + (f32)(s32)((KaldachomPlacement*)obj->anim.placementData)->scale / 15.0f;

    if (((s32)state->baddie.eventFlags & BADDIE_EVENT_FOOTSTEP) != 0) {
        state->baddie.eventFlags &= ~BADDIE_EVENT_FOOTSTEP;
        Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy211_273);
    }
    if (((s32)state->baddie.eventFlags & KALDACHOM_EVENT_CLIMB_FX) != 0) {
        control->climbFxIndex = randomGetRange(0, 2);
        state->baddie.eventFlags &= ~KALDACHOM_EVENT_CLIMB_FX;
        Sfx_PlayFromObject(obj, SFXTRIG_mn_impyflap16);
        for (spawnCount = (2 - control->climbFxIndex) * 10; spawnCount != 0; spawnCount--) {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, KALDACHOM_PARTFX_CLIMB, 0, 4, -1, &gKaldachomMouthSpawnScratch);
        }
    }
    if (((s32)state->baddie.eventFlags & KALDACHOM_EVENT_LOWER_PROJECTILE) != 0) {
        state->baddie.eventFlags &= ~KALDACHOM_EVENT_LOWER_PROJECTILE;
        kaldachom_spawnMouthProjectile(obj, objectState, 0);
    }
    if (((s32)state->baddie.eventFlags & KALDACHOM_EVENT_UPPER_PROJECTILE) != 0) {
        state->baddie.eventFlags &= ~KALDACHOM_EVENT_UPPER_PROJECTILE;
        kaldachom_spawnMouthProjectile(obj, objectState, 1);
    }
    if (((s32)state->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0) {
        state->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        Sfx_PlayFromObject(obj, SFXTRIG_mn_cling03);
    }
    if (((s32)state->baddie.eventFlags & KALDACHOM_EVENT_ATTACK_FX) != 0) {
        control->climbFxIndex = 3;
        spawnCount = 10;
        do {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, KALDACHOM_PARTFX_ATTACK, 0, 4, -1, &gKaldachomMouthSpawnScratch);
            spawnCount--;
        } while (spawnCount != 0);
        state->baddie.eventFlags &= ~KALDACHOM_EVENT_ATTACK_FX;
    }
}

ObjectDescriptor12 gKaldachomObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)kaldachom_initialise,
    (ObjectDescriptorCallback)kaldachom_release,
    0,
    (ObjectDescriptorCallback)kaldachom_init,
    (ObjectDescriptorCallback)kaldachom_update,
    (ObjectDescriptorCallback)kaldachom_hitDetect,
    (ObjectDescriptorCallback)kaldachom_render,
    (ObjectDescriptorCallback)kaldachom_free,
    (ObjectDescriptorCallback)kaldachom_getObjectTypeId,
    kaldachom_getExtraSize,
    (ObjectDescriptorCallback)kaldachom_getControlMode,
    (ObjectDescriptorCallback)kaldachom_func0B,
};

const f32 gKaldachomTextureIdScale[] = {127.0f};
const f32 gKaldachomPi[] = {3.1415927f};
const f32 gKaldachomAngleUnitScale[] = {32768.0f};

void kaldachom_updateCombat(GameObject* obj, GroundBaddieState* objectStateAddress, GroundBaddieState* stateAddress) {
    KaldachomControl* control;
    GameObject* playerObj;
    int hitResult;
    u8 dustAlpha;
    KaldachomCombatStack stack;
    u16 hitType;
    u16 hitAux1;
    u16 hitAux2;

    control = ((KaldachomControl*)((KaldachomState*)objectStateAddress)->ground.control);
    stack.params = gKaldachomCombatParams;
    playerObj = Obj_GetPlayerObject();
    if (stateAddress->baddie.targetObj != NULL) {
        GameObject* target = (GameObject*)stateAddress->baddie.targetObj;
        stack.dx = target->anim.worldPosX - obj->anim.worldPosX;
        stack.dy = target->anim.worldPosY - obj->anim.worldPosY;
        stack.dz = target->anim.worldPosZ - obj->anim.worldPosZ;
        stateAddress->baddie.targetDistance =
            sqrtf(stack.dz * stack.dz + (stack.dx * stack.dx + stack.dy * stack.dy));
    }
    (*gBaddieControlInterface)
        ->processMessages(obj, stateAddress, &objectStateAddress->routeNav,
                          objectStateAddress->gameBitB, NULL, 0, 0, 4);
    (*gBaddieControlInterface)->getTargetGeometry(obj, playerObj, 4, &hitType, &hitAux1, &hitAux2);
    if ((hitType == 1) || (hitType == 2)) {
        hitResult = (*gBaddieControlInterface)
                        ->updateHitReaction(obj, stateAddress, &objectStateAddress->routeNav,
                                            objectStateAddress->gameBitB, NULL, NULL, 1,
                                            &gKaldachomHitLightWork);
        if (hitResult != 0) {
            if ((hitResult != 0x10) && (hitResult != 0x11)) {
                objDoHitParticleFx((void*)obj, 0.014f, &gKaldachomHitLightWork, 3, 0);
                (*gPlayerInterface)->setState(obj, stateAddress, 4);
                stateAddress->baddie.hitPoints -= 1;
                Obj_SetModelColorFadeRecursive(obj, 0xf, 200, 0, 0, 1);
                Sfx_PlayFromObject(obj, SFXTRIG_stftest);
            }
            if (stateAddress->baddie.hitPoints < 1) {
                stateAddress->baddie.substate = 2;
            }
        }
    } else {
        hitResult = (*gBaddieControlInterface)
                        ->updateHitReaction(obj, stateAddress, &objectStateAddress->routeNav,
                                            objectStateAddress->gameBitB, NULL, NULL, 1,
                                            &gKaldachomHitLightWork);
        if (hitResult != 0) {
            if (hitResult != 0x11) {
                if ((hitResult != 0x10) && (control->hitFlashTimer < 64.0f)) {
                    kaldachom_spawnDustEffects(obj, control);
                    gKaldachomHitLightWork.scale = 1.0f;
                    gKaldachomHitLightWork.rotZ = 0;
                    gKaldachomHitLightWork.rotY = 0;
                    gKaldachomHitLightWork.rotX = 0;
                    (*gKaldachomEffectResource)
                        ->spawn(NULL, 1, &gKaldachomHitLightWork, 0x401, -1,
                                (StaffCollisionColorArgs*)((u8*)&stack + 0xc));
                    playerSetHitReactionVariant(playerObj, 2);
                    (*gPlayerInterface)->setState(obj, stateAddress, 5);
                    objDoHitParticleFx((void*)obj, 0.014f, &gKaldachomHitLightWork, 4, 0);
                    Sfx_PlayFromObject(obj, SFXTRIG_swdout1);
                }
            } else {
                if (stateAddress->baddie.substate != 1) {
                    (*gPlayerInterface)->setState(obj, stateAddress, 6);
                    stateAddress->baddie.moveJustStartedB = 1;
                    stateAddress->baddie.moveJustStartedA = 1;
                    stateAddress->baddie.substate = 1;
                    objDoHitParticleFx((void*)obj, 0.014f, &gKaldachomHitLightWork, 1, 0);
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_call3);
                }
            }
        }
        if (stateAddress->baddie.hitPoints < 1) {
            stateAddress->baddie.substate = 2;
        }
    }

    if (control->spawnedDustObj != NULL) {
        if (control->hitFlashTimer <= 0.0f) {
            f32 zero = 0.0f;
            control->spawnedDustObj->anim.alpha = 0;
            control->hitFlashTimer = zero;
        } else {
            dustAlpha = randomGetRange(0, (u8)(s32)control->hitFlashTimer);
            control->spawnedDustObj->anim.alpha = dustAlpha;
            control->spawnedDustObj->anim.rotZ = obj->anim.rotZ;
            control->spawnedDustObj->anim.rotY = obj->anim.rotY;
            control->spawnedDustObj->anim.rotX = obj->anim.rotX;
            control->hitFlashTimer -= 4.0f * timeDelta;
        }
    }
}

void kaldachom_func0B(void) {
}

s16 kaldachom_getControlMode(GameObject* obj) {
    return ((KaldachomState*)obj->extra)->ground.baddie.controlMode;
}

int kaldachom_getExtraSize(void) {
    return sizeof(KaldachomState);
}

int kaldachom_getObjectTypeId(void) {
    return KALDACHOM_OBJECT_TYPE_ID;
}

void kaldachom_free(GameObject* obj) {
    KaldachomState* state;

    state = obj->extra;
    objFreeObjectType(obj, KALDACHOM_OBJECT_GROUP);
    (*gBaddieControlInterface)->releaseState(obj, state, 0x20);
}

void kaldachom_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    KaldachomState* state;
    KaldachomControl* control;

    state = obj->extra;
    if (visible != 0) {
        switch (obj->userData1) {
        case 0:
            if (state->ground.glowAlpha) {
                objSetGlowColor(200, 0, 0, (int)state->ground.glowAlpha);
            }
            objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, 1.0f);
            if ((state->ground.flags400 & 0x60) != 0) {
                objDoParticleFx(obj, 1.0f, 3, state->ground.glowAlpha, 0);
            }
            control = ((KaldachomControl*)state->ground.control);
            ObjPath_GetPointWorldPosition(obj, 2, &control->upperMouthPosX, &control->upperMouthPosY,
                                          &control->upperMouthPosZ, 0);
            ObjPath_GetPointWorldPosition(obj, 1, &control->lowerMouthPosX, &control->lowerMouthPosY,
                                          &control->lowerMouthPosZ, 0);
            break;
        }
    }
}

void kaldachom_hitDetect(GameObject* obj) {
    (void)obj;
}

void kaldachom_update(GameObject* obj) {
    int cond;
    GameObject* player;
    int texture;
    int ref;
    ObjPlacement* placement;
    KaldachomState* objectState;
    f32 scrollPhase;

    objectState = obj->extra;
    placement = (ObjPlacement*)obj->anim.placementData;
    if (obj->userData1 != 0) {
        if ((objectState->ground.baddie.substate != 3) &&
            (cond = (*gMapEventInterface)->shouldNotSaveTime(placement->ident), cond != 0)) {
            (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)objectState, 8, 6, 0, 0x26, 20.0f);
            objectState->ground.targetState = 0;
            Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy211);
            ObjAnim_SetCurrentMove(obj, 4, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            objectState->ground.baddie.moveDone = 0;
            obj->anim.alpha = 0xff;
            obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
    } else {
        ref = (*gBaddieControlInterface)->isObjectValid(obj, objectState, 0);
        if (ref == 0) {
            objectState->ground.targetState = 0;
        } else {
            kaldachom_updateCombat(obj, (GroundBaddieState*)objectState, (GroundBaddieState*)objectState);
            if (objectState->ground.targetState == 0) {
                texture = (int)objectState->ground.control;
                ((KaldachomControl*)texture)->pullupSfxTimer -= timeDelta;
                if (((KaldachomControl*)texture)->pullupSfxTimer <= 0.0f) {
                    Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy111);
                    ((KaldachomControl*)texture)->pullupSfxTimer = randomGetRange(300, 600);
                }
                player = Obj_GetPlayerObject();
                objectState->ground.baddie.targetObj = player;
                if (objectState->ground.baddie.controlMode != KALDACHOM_CONTROL_MODE_RETURN) {
                    (*gPlayerInterface)->rotateTowardTarget(obj, objectState, timeDelta, 5);
                }
                ref = (int)(*gBaddieControlInterface)
                          ->findAggroTarget(obj, objectState, (f32)(u32)objectState->ground.aggroRange, 0x8000);
                if ((void*)ref != NULL) {
                    (*gBaddieControlInterface)
                        ->startHitReaction(obj, objectState, (char*)objectState + 0x35c, objectState->ground.gameBitB, NULL, 0,
                                           0, 4, -1);
                    objectState->ground.baddie.hasTarget = 0;
                    objectState->ground.targetState = 1;
                }
            } else {
                ref = (int)objectState->ground.control;
                texture = (int)objFindTexture(obj, 0, 0);
                ((KaldachomControl*)ref)->textureScrollAngle += 0x1000;
                scrollPhase =
                    mathSinf((gKaldachomPi[0] * (f32)(s32)((KaldachomControl*)ref)->textureScrollAngle) / gKaldachomAngleUnitScale[0]);
                scrollPhase = 1.0f + scrollPhase;
                ((ObjTextureRuntimeSlot*)texture)->textureId = (int)(gKaldachomTextureIdScale[0] * scrollPhase);
                player = Obj_GetPlayerObject();
                objectState->ground.baddie.targetObj = player;
                kaldachom_handleAnimEvents(obj, objectState, &objectState->ground);
                (*gBaddieControlInterface)->updateGravity(obj, objectState, 0.0f, -1);
                if (objectState->ground.baddie.controlMode != KALDACHOM_CONTROL_MODE_RETURN) {
                    (*gPlayerInterface)->rotateTowardTarget(obj, objectState, timeDelta, 5);
                }
                objectState->ground.savedPendingParentObj = obj->pendingParentObj;
                obj->pendingParentObj = 0;
                (*gPlayerInterface)
                    ->update(obj, objectState, timeDelta, timeDelta, &gKaldachomStateHandlersA,
                             &gKaldachomStateHandlersB);
                obj->pendingParentObj = objectState->ground.savedPendingParentObj;
            }
        }
    }
}

KaldachomStateHandler gKaldachomStateHandlersA[8];

void kaldachom_init(GameObject* obj, KaldachomPlacement* placement, int flags) {
    KaldachomState* state;
    KaldachomControl* control;
    GameObject* player;
    u8 initMode;

    state = obj->extra;
    initMode = 6;
    if (flags != 0) {
        initMode |= 1;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)placement, (u8*)state, 8, 6, 0, initMode, 20.0f);
    obj->animEventCallback = NULL;
    control = ((KaldachomControl*)state->ground.control);
    ObjAnim_SetCurrentMove(obj, 4, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
    obj->anim.currentMoveProgress = 0.01f;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    (*gPlayerInterface)->setState(obj, state, 0);
    *(u16*)&state->ground.baddie.substate = 0;
    state->ground.baddie.moveSpeed = 0.01f;
    state->ground.baddie.animSpeedA = 0.0f;
    player = Obj_GetPlayerObject();
    state->ground.baddie.targetObj = player;
    state->ground.baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
    control->pullupSfxTimer = randomGetRange(300, 600);
    control->idleAnimTimer = randomGetRange(0, 499);
    control->unk3C = 0.0f;
    control->spawnedDustObj = NULL;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    obj->anim.rootMotionScale = 0.5f + (f32)(s32)placement->scale / 15.0f;
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, (int)(16.0f * obj->anim.rootMotionScale));
    if (flags == 0) {
        gKaldachomEffectResource = Resource_Acquire(KALDACHOM_EFFECT_RESOURCE_ID, 1);
    }
}

void kaldachom_release(void) {
}

void kaldachom_initialise(void) {
    gKaldachomStateHandlersA[0] = kaldachom_stateHandlerA00;
    gKaldachomStateHandlersA[1] = kaldachom_stateHandlerA01;
    gKaldachomStateHandlersA[2] = kaldachom_stateHandlerA02;
    gKaldachomStateHandlersA[3] = kaldachom_stateHandlerA03;
    gKaldachomStateHandlersA[4] = kaldachom_stateHandlerA04;
    gKaldachomStateHandlersA[5] = kaldachom_stateHandlerA05;
    gKaldachomStateHandlersA[6] = kaldachom_stateHandlerA06;
    gKaldachomStateHandlersA[7] = kaldachom_stateHandlerA07;
    gKaldachomStateHandlersB[0] = kaldachom_stateHandlerB00;
    gKaldachomStateHandlersB[1] = kaldachom_stateHandlerB01;
    gKaldachomStateHandlersB[2] = kaldachom_stateHandlerB02;
    gKaldachomStateHandlersB[3] = kaldachom_stateHandlerB03;
    gKaldachomStateHandlersB[4] = kaldachom_stateHandlerB04;
    gKaldachomStateHandlersB[5] = kaldachom_stateHandlerB05;
}

