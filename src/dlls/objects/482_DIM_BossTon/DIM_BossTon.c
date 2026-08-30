/*
 * DIM_BossTon (DLL 0x1E2) - the DarkIce Mines boss tonsil target.
 * It coordinates the hit-reaction state machine, boss-route game bits,
 * lighting, sequence events, and hit effects for the encounter.
 */
#include "dlls/objects/482_DIM_BossTon.h"

#include "dlls/objects/480_DIM_Boss.h"
#include "main/audio/music_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/pad.h"
#include "main/player_control_interface.h"
#include "main/render_envfx_api.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "main/dll/partfx_interface.h"
#include "main/mapEventTypes.h"
#include "main/model_light.h"
extern f32 gDIMbosstonsilRouteDelayTimer;
extern f32 gDIMbosstonsilNextRumbleTime;
extern f32 gDIMbosstonsilRumbleElapsed;
extern f32 gDIMbosstonsilFightTimer;

#define DIMBOSSTONSIL_HIT_EFFECT_ID     0x4b2
#define DIMBOSSTONSIL_HIT_EFFECT_ALT_ID 0x4b3
#define DIMBOSSTONSIL_PRIMARY_HIT_SFX   0x18a
#define DIMBOSSTONSIL_ALT_HIT_SFX       0x18b
#define DIMBOSSTONSIL_NORMAL_HIT_SFX    0x18c
/* The canonical unit header owns the shared tonsil-hit gamebit. */
#define DIMBOSSTONSIL_ADVANCE_MSG 0xe0001
/* particle-spawn flag word: bit 0x200000 | bit 0x1 */
#define DIMBOSSTONSIL_HIT_FX_FLAGS 0x200001

#define DIMBOSSTONSIL_OBJECT_TYPE 0x4b

#define DIMBOSSTONSIL_ANIM_EVENT_START_STEAM   1
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA   2
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA  3
#define DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT  4
#define DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT 5

#define DIMBOSSTONSIL_MAP_DIR               0x1c
#define DIMBOSSTONSIL_MAP_AREA              1
#define DIMBOSSTONSIL_STEAM_ENVFX           0xd8
#define DIMBOSSTONSIL_STEAM_MUSIC           0xee
#define DIMBOSSTONSIL_RUMBLE_SFX            0x189
#define DIMBOSSTONSIL_STATE_FLAG_START_MOVE 2

int DIMbosstonsil_updateHitReaction(GameObject* obj, GroundBaddieState* state, int unused) {
    if (state->baddie.moveJustStartedA != 0) {
        (*gPlayerInterface)->setState(obj, state, 1);
    }
    if (state->baddie.moveDone != 0) {
        return 1;
    }
    return 0;
}

int DIMbosstonsil_enableHitReaction(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedB != 0) {
        state->baddie.moveJustStartedA = 1;
        (*gPlayerInterface)->setState(obj, state, 0);
    }
    return 0;
}

int DIMbosstonsil_chooseHitReaction(GameObject* obj, GroundBaddieState* state) {
    u16 moveId;
    u16 unused1;
    u16 unused2;

    if (state->baddie.moveJustStartedA != 0) {
        gDIMbosstonsilNextRumbleTime = gDIMbosstonsilRumbleElapsed;
        (*gBaddieControlInterface)->getTargetGeometry(obj, Obj_GetPlayerObject(), 4, &moveId, &unused1, &unused2);
        switch (moveId) {
        case 0:
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
            break;
        case 1:
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 3, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
            break;
        case 2:
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 2, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
            break;
        default:
            if (state->baddie.moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 4, 0.0f, 0);
                state->baddie.moveDone = 0;
            }
            break;
        }
        state->baddie.moveSpeed = 0.005f;
    }
    return 0;
}

int DIMbosstonsil_startIdleHitReaction(GameObject* obj, GroundBaddieState* state) {
    if (state->baddie.moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = 0.01f;
    return 0;
}
const f32 gDIMbosstonsilThirty[] = {30.0f};
const f32 gDIMbosstonsilFifty[] = {50.0f};

void DIMbosstonsil_checkHit(GameObject* obj, GroundBaddieState* state) {
    GameObject* hitObj;
    int modelPart;
    u32 hitVolume;
    PartFxSpawnParams spawnArgs;
    f32* spawnPos;
    int hit;

    hit = ObjHits_GetPriorityHit(obj, &hitObj, &modelPart, &hitVolume);
    if (hit != 0) {
        spawnPos = &spawnArgs.posX;
        {
            ObjModel* model = obj->anim.modelBanks[obj->anim.bankIndex];
            f32(*modelPos)[4] = (f32(*)[4])model->activeHitVolumeSpheres;
            spawnPos[0] = playerMapOffsetX + modelPos[modelPart][1];
            spawnPos[1] = modelPos[modelPart][2];
            spawnPos[2] = playerMapOffsetZ + modelPos[modelPart][3];
        }
        (*gPartfxInterface)
            ->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ID, &spawnArgs, DIMBOSSTONSIL_HIT_FX_FLAGS, -1, NULL);
        (*gPartfxInterface)
            ->spawnObject(obj, DIMBOSSTONSIL_HIT_EFFECT_ALT_ID, &spawnArgs, DIMBOSSTONSIL_HIT_FX_FLAGS, -1, NULL);
        objDoHitParticleFx(obj, 0.028f, &spawnArgs, 3, 0);
        Sfx_PlayFromObject(obj, DIMBOSSTONSIL_PRIMARY_HIT_SFX);
        doRumble(16.0f);
        if (state->baddie.hitPoints != 0) {
            Sfx_PlayFromObject(obj, DIMBOSSTONSIL_ALT_HIT_SFX);
        } else {
            Sfx_PlayFromObject(obj, DIMBOSSTONSIL_NORMAL_HIT_SFX);
        }
        CameraShake_SetOffset(3.0f);
        if (gDIMbosstonsilRouteDelayTimer == 0.0f) {
            state->baddie.moveJustStartedA = 1;
            state->baddie.moveDone = 0;
            state->baddie.lastHitPriority = hit;
            state->baddie.hitPoints--;
            gDIMbosstonsilRoutePhase++;
            mainSetBits(DIMBOSSTONSIL_HIT_GAMEBIT, gDIMbosstonsilRoutePhase);
            if (gDIMbosstonsilRoutePhase == 3 || gDIMbosstonsilRoutePhase == 7) {
                gDIMbosstonsilRouteDelayTimer = 90.0f;
            } else {
                gDIMbosstonsilRouteDelayTimer = 0.0f;
            }
            (*gPlayerInterface)->setState(obj, state, 1);
            state->baddie.substate = 1;
            ObjMsg_SendToObject(hitObj, DIMBOSSTONSIL_ADVANCE_MSG, obj, 0);
        }
    }
}

/* ObjHitsPriorityState.flags uses the canonical enabled bit. */
/* ObjAnimComponent.resetHitboxMode uses INTERACT_FLAG_DISABLED. */

/* The DIM_Boss header owns the shared icicle-defeat gamebit. */
#define DIMBOSSTONSIL_GAMEBIT_ROUTE_LOW  0x268
#define DIMBOSSTONSIL_GAMEBIT_ROUTE_HIGH 0x311

#define DIMBOSSTONSIL_ROUTE_HIGH_THRESHOLD  7
#define DIMBOSSTONSIL_ROUTE_SPLIT_THRESHOLD 3

void dimBossTonsil_newState_hitFightMain(GameObject* obj, ObjSeqState* animUpdate, GroundBaddieState* state,
                                         GroundBaddieState* updateState) {
    f32 timer;

    timer = 0.0f;

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;

    updateState->baddie.physicsActive = 1;

    (*gBaddieControlInterface)->updateGravity(obj, updateState, timer, 1);

    (*gBaddieControlInterface)
        ->processMessages(obj, updateState, &state->routeNav, state->gameBitB, &state->subMode, 0,
                          0, 0);

    if (gDIMbosstonsilFightTimer != 0.0f) {
        gDIMbosstonsilFightTimer = gDIMbosstonsilFightTimer - timeDelta;
        timer = gDIMbosstonsilFightTimer / 8.0f;
        if (gDIMbosstonsilFightTimer <= 1.0f) {
            gDIMbosstonsilFightTimer = 0.0f;
            updateState->baddie.hasTarget = 0;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            mainSetBits(DIMBOSS_GAMEBIT_ICICLE_DEFEATED, 0);
            if (gDIMbosstonsilRoutePhase >= DIMBOSSTONSIL_ROUTE_HIGH_THRESHOLD) {
                mainSetBits(DIMBOSSTONSIL_GAMEBIT_ROUTE_HIGH, 1);
            } else {
                mainSetBits(DIMBOSSTONSIL_GAMEBIT_ROUTE_LOW, 1);
            }
        }
    } else {
        timer += 100.0f;
    }

    if (gDIMbosstonsilRumbleElapsed >= gDIMbosstonsilNextRumbleTime) {
        Sfx_PlayFromObject(obj, DIMBOSSTONSIL_RUMBLE_SFX);
        if (timer > 100.0f) {
            timer = 100.0f;
        }
        if (timer < gDIMbosstonsilThirty[0]) {
            timer = gDIMbosstonsilThirty[0];
        }
        gDIMbosstonsilNextRumbleTime = gDIMbosstonsilNextRumbleTime + timer;
        doRumble(8.0f);
    }

    gDIMbosstonsilRumbleElapsed = gDIMbosstonsilRumbleElapsed + timeDelta;
    DIMbosstonsil_checkHit(obj, updateState);

    if (gDIMbosstonsilRouteDelayTimer != 0.0f) {
        gDIMbosstonsilRouteDelayTimer = gDIMbosstonsilRouteDelayTimer - timeDelta;
        if (gDIMbosstonsilRouteDelayTimer <= 0.0f) {
            gDIMbosstonsilRouteDelayTimer = 0.0f;
            updateState->baddie.hasTarget = 0;
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
            mainSetBits(DIMBOSS_GAMEBIT_ICICLE_DEFEATED, 0);
            if (gDIMbosstonsilRoutePhase == DIMBOSSTONSIL_ROUTE_SPLIT_THRESHOLD) {
                mainSetBits(DIMBOSSTONSIL_GAMEBIT_ROUTE_LOW, 1);
            } else {
                mainSetBits(DIMBOSSTONSIL_GAMEBIT_ROUTE_HIGH, 1);
            }
        }
    }

    state->savedPendingParentObj = obj->pendingParentObj;
    obj->pendingParentObj = (void*)0;

    (*gPlayerInterface)
        ->update(obj, updateState, timeDelta, timeDelta, &gDIMbosstonsilStateHandlers, &gDIMbosstonsilSubstateHandlers);

    obj->pendingParentObj = state->savedPendingParentObj;
}

#define DIMBOSSTONSIL_OBJGROUP 3
#define DIMBOSSTONSIL_PARTFX   0x4bd

DIMbosstonsilStateHandlerTable gDIMbosstonsilStateHandlers;
DIMbosstonsilSubstateHandlerTable gDIMbosstonsilSubstateHandlers;
f32 gDIMbosstonsilFightTimer;
f32 gDIMbosstonsilRumbleElapsed;
f32 gDIMbosstonsilNextRumbleTime;
f32 gDIMbosstonsilRouteDelayTimer;
s8 gDIMbosstonsilRoutePhase;
ModelLightStruct* gDIMbosstonsilLight;

int DIMbosstonsil_SeqFn(GameObject* obj, u32 unused, ObjSeqState* animUpdate) {
    GroundBaddieState* state;
    const DIMbosstonsilPlacementView* config;
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;
    s16 lightValue;
    int eventIndex;
    int eventId;
    int subMode;
    int animOk;

    state = obj->extra;
    config = (const DIMbosstonsilPlacementView*)obj->anim.placementData;

    if (gDIMbosstonsilLight != NULL) {
        modelLightStruct_getSpecularColor((ModelLightStruct*)gDIMbosstonsilLight, &red, &green, &blue, &alpha);
        modelLightStruct_setGlowColor((ModelLightStruct*)gDIMbosstonsilLight, red, green, blue, 0xc0);
        if (gDIMbosstonsilLight->glowType != 0 && gDIMbosstonsilLight->enabled != 0) {
            lightValue = gDIMbosstonsilLight->glowAlpha + gDIMbosstonsilLight->glowAlphaStep;
            if (lightValue < 0) {
                lightValue = 0;
                gDIMbosstonsilLight->glowAlphaStep = 0;
            } else if (lightValue > 0xc) {
                lightValue = lightValue + randomGetRange(-0xc, 0xc);
                if (lightValue > 0xff) {
                    lightValue = 0xff;
                    gDIMbosstonsilLight->glowAlphaStep = 0;
                }
            }
            gDIMbosstonsilLight->glowAlpha = lightValue;
        }
    }

    if (obj->userData1 != 0) {
        return 0;
    }

    for (eventIndex = 0; eventIndex < (int)(u32)animUpdate->eventCount; eventIndex++) {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId) {
        case DIMBOSSTONSIL_ANIM_EVENT_START_STEAM:
            skySetLightsEnabled(7, 1, 0);
            skySetLightDirection(7, -0.1f, -0.1f, 1.0f);
            skySetBaseColor(7, 0xff, 0xb4, 0xb4, 0x7f, 0x28);
            getEnvfxAct(obj, obj, DIMBOSSTONSIL_STEAM_ENVFX, 0);
            Music_Trigger(DIMBOSSTONSIL_STEAM_MUSIC, 1);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSSTONSIL_MAP_DIR, DIMBOSSTONSIL_MAP_AREA, 1);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_AREA:
            (*gMapEventInterface)->setObjGroupStatus(DIMBOSSTONSIL_MAP_DIR, DIMBOSSTONSIL_MAP_AREA, 0);
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_ENABLE_LIGHT:
            if (gDIMbosstonsilLight != NULL) {
                modelLightStruct_setEnabled(gDIMbosstonsilLight, 1, 1.0f);
            }
            break;
        case DIMBOSSTONSIL_ANIM_EVENT_DISABLE_LIGHT:
            if (gDIMbosstonsilLight != NULL) {
                modelLightStruct_setEnabled(gDIMbosstonsilLight, 0, 1.0f);
            }
            break;
        }
    }

    if (gDIMbosstonsilRumbleElapsed >= gDIMbosstonsilNextRumbleTime) {
        Sfx_PlayFromObject(obj, DIMBOSSTONSIL_RUMBLE_SFX);
        gDIMbosstonsilNextRumbleTime += 100.0f;
        doRumble(8.0f);
    }
    gDIMbosstonsilRumbleElapsed += timeDelta;

    if (obj->seqIndex != -1) {
        animOk = (*gBaddieControlInterface)->isObjectValid(obj, state, 1);
        if (animOk == 0) {
            return 1;
        }
        if ((state->gameBitC != -1) && (mainGetBit(state->gameBitC) != 0)) {
            (*gObjectTriggerInterface)->yield(animUpdate, config->eventId);
            state->gameBitC = -1;
        }

        subMode = state->subMode;
        switch (subMode) {
        case 2:
            animUpdate->flags = 0;
            dimBossTonsil_newState_hitFightMain(obj, animUpdate, state, state);
            if (state->subMode == 1) {
                state->baddie.substate = 0;
                (*gPlayerInterface)
                    ->update(obj, state, 1.0f, 1.0f, &gDIMbosstonsilStateHandlers, &gDIMbosstonsilSubstateHandlers);
                animUpdate->movementState = 0;
            }
            break;
        case 1:
            animOk = (*gBaddieControlInterface)
                         ->updateSequenceMovement(obj, animUpdate, (char*)state,
                                                  &gDIMbosstonsilStateHandlers, &gDIMbosstonsilSubstateHandlers, 0);
            if (animOk != 0) {
                (*gBaddieControlInterface)->updateGravity(obj, state, 0.0f, 1);
            }
            break;
        case 0:
        default:
            animUpdate->flags = -1;
            animUpdate->flags &= ~OBJSEQ_FLAG_TEXTURE_ANIM_TRACKS;
            break;
        }
    }

    if (obj->seqIndex == -1) {
        state->flags400 |= DIMBOSSTONSIL_STATE_FLAG_START_MOVE;
        return 0;
    }

    return 0;
}

void DIMbosstonsil_func0B(void) {
}

int DIMbosstonsil_getControlMode(GameObject* obj) {
    return ((GroundBaddieState*)obj->extra)->baddie.controlMode;
}

int DIMbosstonsil_getExtraSize(void) {
    return sizeof(GroundBaddieState);
}

int DIMbosstonsil_getObjectTypeId(void) {
    return DIMBOSSTONSIL_OBJECT_TYPE;
}

void DIMbosstonsil_free(GameObject* obj) {
    GroundBaddieState* state;

    state = obj->extra;
    objFreeObjectType(obj, DIMBOSSTONSIL_OBJGROUP);
    (*gBaddieControlInterface)->releaseState(obj, state, 1);
    if (gDIMbosstonsilLight != NULL) {
        ModelLightStruct_free(gDIMbosstonsilLight);
    }
}

void DIMbosstonsil_render(GameObject* obj, u32 renderArg2, u32 renderArg3, u32 renderArg4, u32 renderArg5,
                          char visible) {
    struct {
        f32 x;
        f32 y;
        f32 z;
    } pathPoint;
    int spawnArgs[3];
    f32* pathX;

    if (visible != 0) {
        switch (obj->userData1) {
        case 0: {
            objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, (double)1.0f);

            ObjPath_GetPointWorldPosition(obj, 1, (pathX = &pathPoint.x), &pathPoint.y, &pathPoint.z, 0);
            (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_PARTFX, spawnArgs, 0x200001, -1, NULL);

            ObjPath_GetPointWorldPosition(obj, 0, pathX, &pathPoint.y, &pathPoint.z, 0);
            (*gPartfxInterface)->spawnObject(obj, DIMBOSSTONSIL_PARTFX, spawnArgs, 0x200001, -1, NULL);

            if (gDIMbosstonsilLight != NULL && gDIMbosstonsilLight->glowType != 0 &&
                gDIMbosstonsilLight->enabled != 0) {
                modelLightStruct_setPosition(gDIMbosstonsilLight, pathPoint.x, pathPoint.y, pathPoint.z);
                queueGlowRender(gDIMbosstonsilLight);
            }
            break;
        }
        }
    }
}

void DIMbosstonsil_hitDetect(GameObject* obj) {
    (*gPlayerInterface)->updateVelocityState(obj, obj->extra, &gDIMbosstonsilStateHandlers);
}

void DIMbosstonsil_update(GameObject* obj) {
    GroundBaddieState* state;
    const DIMbosstonsilPlacementView* config;
    u8 red;
    u8 green;
    u8 blue;
    u8 alpha;

    state = obj->extra;
    config = (const DIMbosstonsilPlacementView*)obj->anim.placementData;

    if (obj->userData1 != 0) {
        return;
    }

    if (obj->userData2 == 0) {
        obj->anim.localPosX = config->base.posX;
        obj->anim.localPosY = config->base.posY;
        obj->anim.localPosZ = config->base.posZ;
        (*gObjectTriggerInterface)->runSequence((int)config->animObjectId, obj, -1);
        obj->userData2 = 1;
        return;
    }

    if ((state->flags400 & DIMBOSSTONSIL_STATE_FLAG_START_MOVE) != 0) {
        gDIMbosstonsilFightTimer = 780.0f;
        (*gBaddieControlInterface)
            ->startHitReaction(obj, state, &state->routeNav, state->gameBitB, &state->subMode, 0, 0,
                               0, 1);
        state->flags400 &= ~DIMBOSSTONSIL_STATE_FLAG_START_MOVE;
    }

    if ((*gBaddieControlInterface)->isObjectValid(obj, state, 1) == 0) {
        return;
    }

    state->baddie.targetObj = Obj_GetPlayerObject();
    dimBossTonsil_newState_hitFightMain(obj, NULL, state, state);

    if (gDIMbosstonsilLight == NULL) {
        return;
    }

    modelLightStruct_getSpecularColor((ModelLightStruct*)gDIMbosstonsilLight, &red, &green, &blue, &alpha);
    modelLightStruct_setGlowColor((ModelLightStruct*)gDIMbosstonsilLight, red, green, blue, 0xc0);

    if (gDIMbosstonsilLight->glowType == 0) {
        return;
    }
    if (gDIMbosstonsilLight->enabled == 0) {
        return;
    }

    {
        s16 glowAlpha;
        int nextGlowAlpha;
        nextGlowAlpha = gDIMbosstonsilLight->glowAlpha + gDIMbosstonsilLight->glowAlphaStep;
        glowAlpha = nextGlowAlpha;
        if (glowAlpha < 0) {
            glowAlpha = 0;
            gDIMbosstonsilLight->glowAlphaStep = 0;
        } else if (glowAlpha > 0xc) {
            int randomOffset = randomGetRange(-0xc, 0xc);
            glowAlpha = (s16)(glowAlpha + randomOffset);
            if (glowAlpha > 0xff) {
                glowAlpha = 0xff;
                gDIMbosstonsilLight->glowAlphaStep = 0;
            }
        }
        gDIMbosstonsilLight->glowAlpha = glowAlpha;
    }
}

void DIMbosstonsil_init(GameObject* obj, u8* placementAddress, int isAltVariant) {
    u8 variant;
    GroundBaddieState* state;

    state = obj->extra;
    variant = 6;
    if (isAltVariant != 0) {
        variant = variant | 1;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, placementAddress, (u8*)state, 2, 2, 0x102, variant, 20.0f);
    obj->animEventCallback = DIMbosstonsil_SeqFn;
    (*gPlayerInterface)->setState(obj, state, 0);
    state->baddie.substate = 0;
    gDIMbosstonsilRoutePhase = mainGetBit(DIMBOSSTONSIL_HIT_GAMEBIT);
    if (gDIMbosstonsilRoutePhase < 3) {
        state->baddie.hitPoints = 3 - gDIMbosstonsilRoutePhase;
    } else {
        state->baddie.hitPoints = 7 - gDIMbosstonsilRoutePhase;
    }
    gDIMbosstonsilFightTimer = 0.0f;
    gDIMbosstonsilRumbleElapsed = 0.0f;
    gDIMbosstonsilRouteDelayTimer = 0.0f;
    gDIMbosstonsilNextRumbleTime = gDIMbosstonsilThirty[0];
    gDIMbosstonsilLight = objCreateLight(0, 1);
    if (gDIMbosstonsilLight != NULL) {
        modelLightStruct_setLightKind(gDIMbosstonsilLight, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(gDIMbosstonsilLight, 0xff, 0, 0, 0x7f);
        modelLightStruct_setSpecularColor(gDIMbosstonsilLight, 0xff, 0, 0, 0x7f);
        modelLightStruct_setDistanceAttenuation(gDIMbosstonsilLight, gDIMbosstonsilThirty[0], gDIMbosstonsilFifty[0]);
        lightSetField4D((ModelLightStruct*)gDIMbosstonsilLight, 1);
        modelLightStruct_setEnabled(gDIMbosstonsilLight, 1, 0.0f);
        modelLightStruct_setGlowProjectionRadius((ModelLightStruct*)gDIMbosstonsilLight, gDIMbosstonsilFifty[0]);
        modelLightStruct_setDiffuseTargetColor(gDIMbosstonsilLight, 0xff, 0x7f, 0, 0x40);
        modelLightStruct_setSpecularTargetColor((ModelLightStruct*)gDIMbosstonsilLight, 0xff, 0x7f, 0, 0x40);
        modelLightStruct_startColorFade(gDIMbosstonsilLight, 2, 0x3c);
        modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)gDIMbosstonsilLight, 1);
        modelLightStruct_setupGlow(gDIMbosstonsilLight, 0, 0xff, 0, 0, 0x7f, gDIMbosstonsilFifty[0]);
    }
}

void DIMbosstonsil_release(void) {
}

void DIMbosstonsil_initialise(void) {
    gDIMbosstonsilStateHandlers.startIdle = DIMbosstonsil_startIdleHitReaction;
    gDIMbosstonsilStateHandlers.choose = DIMbosstonsil_chooseHitReaction;
    gDIMbosstonsilSubstateHandlers.enable = DIMbosstonsil_enableHitReaction;
    gDIMbosstonsilSubstateHandlers.update = DIMbosstonsil_updateHitReaction;
}

ObjectDescriptor12 gDIM_BossTonsilObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    DIMbosstonsil_initialise,
    DIMbosstonsil_release,
    0,
    (ObjectDescriptorCallback)DIMbosstonsil_init,
    (ObjectDescriptorCallback)DIMbosstonsil_update,
    (ObjectDescriptorCallback)DIMbosstonsil_hitDetect,
    (ObjectDescriptorCallback)DIMbosstonsil_render,
    (ObjectDescriptorCallback)DIMbosstonsil_free,
    (ObjectDescriptorCallback)DIMbosstonsil_getObjectTypeId,
    DIMbosstonsil_getExtraSize,
    (ObjectDescriptorCallback)DIMbosstonsil_getControlMode,
    DIMbosstonsil_func0B,
};
