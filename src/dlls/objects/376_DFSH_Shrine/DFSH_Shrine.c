#include "dlls/objects/376_DFSH_Shrine.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/audio/audio_control_api.h"
#include "main/audio/music_api.h"
#include "main/audio/music_trigger_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "dlls/objects/201_Baddie.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/frame_timing.h"
#include "main/game_timer_control_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/mapEvent.h"
#include "main/mapEventTypes.h"
#include "main/map_load.h"
#include "main/model_light.h"
#include "main/obj_message.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/pi_dolphin_api.h"
#include "main/render_envfx_api.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/vecmath.h"
#include "sys/objects.h"

STATIC_ASSERT(sizeof(DFSHShrineFlags) == 0x01);

#define DFSH_SHRINE_MAP_ID 0xB

/* shrine-lantern state machine (state->mode) */
#define DFSH_SHRINE_ENVFX_A 0x78
#define DFSH_SHRINE_ENVFX_B 0x79
#define DFSH_SHRINE_ENVFX_C 0x222

#define DFSH_SHRINE_MODE_IDLE          0 /* orbit/chime; wait for player activation */
#define DFSH_SHRINE_MODE_AWAIT_OPEN    1 /* wait for the open sequence to finish */
#define DFSH_SHRINE_MODE_GRANT_REWARDS 2 /* timed reward-bit granting loop */
#define DFSH_SHRINE_MODE_POST_FINISH   3 /* run success/fail follow-up, then reset */
#define DFSH_SHRINE_MODE_RESET         4 /* clear latches/bits, return to idle */
#define DFSH_SHRINE_MODE_BEGIN_TRANS   5 /* start the intro screen transition */
#define DFSH_SHRINE_MODE_AFTER_FINISH  6 /* one frame after the finish transition */
#define DFSH_SHRINE_MODE_FINISH        7 /* start the finishing screen transition */

#define DFSH_SHRINE_REWARD_BIT(idx)    (rewardTableCursor[0][(idx)])
#define DFSH_SHRINE_REWARD_DELAY(idx)  (rewardTableCursor[0][10 + (idx)])
#define DFSH_SHRINE_TARGET_OBJECT(idx) (((int*)((u8*)rewardTableCursor[0] + 0x3C))[(idx)])


u8 gDFSHShrinePendingReward = 1;

u16 gDFSHShrineRewardTable[50] = {
    246, 2997,  247, 2998,  248,  249,   250,  251,   2995, 2996,  60,   60,    60,   60,    600,   600,   600,
    600, 600,   600, 3000,  3008, 3001,  3009, 3002,  3003, 3004,  3005, 3006,  3007, 4,     36948, 4,     37071,
    4,   37054, 4,   37083, 4,    37063, 4,    37065, 4,    37066, 4,    37067, 4,    37068, 4,     37070,
};

void dfshShrine_updateHoverMotion(int objArg) {
    ObjPlacement* placement;
    DFSHShrineHoverState* state;
    GameObject* player;
    GameObject* obj = (GameObject*)objArg;
    f32 trigA;
    f32 trigB;
    f32 distance;
    int angleDelta;
    int turnStep;
    u8 animEvents[32];

    placement = (ObjPlacement*)obj->anim.placementData;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if ((obj->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        obj->anim.rotX = 0;
        obj->anim.localPosY = placement->posY;
        return;
    }

    state->hoverPhase += (s32)(512.0f * timeDelta);
    state->rollPhase += (s32)(128.0f * timeDelta);
    state->yawPhase += (s32)(192.0f * timeDelta);

    obj->anim.localPosY = 20.0f + (placement->posY + mathSinf((3.1415927f * state->hoverPhase) / 32768.0f));

    trigA = mathSinf((3.1415927f * state->rollPhase) / 32768.0f);
    trigB = mathSinf((3.1415927f * state->hoverPhase) / 32768.0f);
    trigB = trigB + trigA;
    obj->anim.rotZ = 600.0f * trigB;

    trigA = mathSinf((3.1415927f * state->yawPhase) / 32768.0f);
    trigB = mathSinf((3.1415927f * state->hoverPhase) / 32768.0f);
    trigB = trigB + trigA;
    obj->anim.rotY = 600.0f * trigB;

    ObjAnim_AdvanceCurrentMove(obj, 0.005f, timeDelta, (ObjAnimEventList*)animEvents);
    if (player != NULL) {
        angleDelta =
            ((u16)getAngle(obj->anim.worldPosX - player->anim.worldPosX, obj->anim.worldPosZ - player->anim.worldPosZ) -
             ((u16)obj->anim.rotX));
        if (angleDelta > 0x8000) {
            angleDelta -= 0xFFFF;
        }
        if (angleDelta < -0x8000) {
            angleDelta += 0xFFFF;
        }
        turnStep = (s32)(((f32)angleDelta * timeDelta) / 12.0f);
        obj->anim.rotX += turnStep;

        distance = Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX);
        if (distance <= 30.0f) {
            obj->anim.alpha = (u8)(s32)(255.0f * (distance / 30.0f));
        } else {
            obj->anim.alpha = 0xFF;
        }
    }
}

int dfshShrine_processAnimEvents(GameObject* obj, int unusedArg2, ObjSeqState* animUpdate) {
    GameObject* objLocal;
    DFSHShrineHoverState* state;
    GameObject* player;
    int i;
    u8 cmd;

    objLocal = obj;
    state = objLocal->extra;
    player = Obj_GetPlayerObject();
    animUpdate->movementState = 0;
    for (i = 0; i < animUpdate->eventCount; i++) {
        cmd = animUpdate->eventIds[i];
        if (cmd != 0) {
            switch (cmd) {
            case 3:
                state->flags.openedBySequence = 1;
                break;
            case 7:
                objSetAnimStateFlags(player, 1, 1);
                mainSetBits(GAMEBIT_ITEM_TestCombatSpirit_Got, 1);
                mainSetBits(GAMEBIT_FlewToPlanet, 1);
                (*gMapEventInterface)->setMapAct(DFSH_SHRINE_MAP_ID, 2);
                break;
            case 0xE:
                objLocal->anim.flags = (s16)(objLocal->anim.flags | OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, 1.0f);
                }
                break;
            case 0xF:
                objLocal->anim.flags = (s16)(objLocal->anim.flags & ~OBJANIM_FLAG_HIDDEN);
                if (state->light != NULL) {
                    modelLightStruct_setEnabled(state->light, 0, 1.0f);
                }
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int dfshShrine_getExtraSize(void) {
    return sizeof(DFSHShrineState);
}

int dfshShrine_getObjectTypeId(void) {
    return 0;
}

void dfshShrine_free(GameObject* obj) {
    DFSHShrineState* state;

    state = obj->extra;
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    gameTimerStop();
    unlockLevel(mapGetDirIdx(0x1F), 1, 0);
    Music_Trigger(MUSICTRIG_DIM_Snow, 0);
    Music_Trigger(MUSICTRIG_CC_Visit1, 0);
    Music_Trigger(MUSICTRIG_vfp_walkabout, 0);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 0);
    mainSetBits(GAMEBIT_SHRINE_MUSIC_LOCK, 1);
}

void dfshShrine_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    DFSHShrineState* state;
    ModelLightStruct* light;
    s32 isVisible;

    state = obj->extra;
    isVisible = visible;
    if (isVisible == 0) {
        light = state->light;
        if (light != NULL) {
            modelLightStruct_setEnabled(light, 0, 1.0f);
        }
    } else {
        light = state->light;
        if (light != NULL) {
            modelLightStruct_setEnabled(light, 1, 1.0f);
        }
        objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
        objDoParticleFx(obj, 1.0f, 7, 1.0f, state->light);
    }
}

ObjectDescriptor gDFSHShrineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dfshShrine_initialise,
    (ObjectDescriptorCallback)dfshShrine_release,
    0,
    (ObjectDescriptorCallback)dfshShrine_init,
    (ObjectDescriptorCallback)dfshShrine_update,
    (ObjectDescriptorCallback)dfshShrine_hitDetect,
    (ObjectDescriptorCallback)dfshShrine_render,
    (ObjectDescriptorCallback)dfshShrine_free,
    (ObjectDescriptorCallback)dfshShrine_getObjectTypeId,
    dfshShrine_getExtraSize,
};

void dfshShrine_hitDetect(void) {
}

void dfshShrine_update(GameObject* obj) {
    u16* rewardTableCursor[1];
    DFSHShrineState* state;
    GameObject* player;
    s16 i;
    u8 anyMissing;
    u16* required;

    rewardTableCursor[0] = gDFSHShrineRewardTable;
    state = obj->extra;
    player = Obj_GetPlayerObject();
    if (obj->userData1 != 0) {
        obj->userData1 = obj->userData1 - 1;
        if (obj->userData1 == 0) {
            skySetSlotFlag80(7, 1);
            getEnvfxAct(obj, player, DFSH_SHRINE_ENVFX_A, 0);
            getEnvfxAct(obj, player, DFSH_SHRINE_ENVFX_B, 0);
            getEnvfxAct(obj, player, DFSH_SHRINE_ENVFX_C, 0);
        }
    }
    dfshShrine_updateHoverMotion((int)obj);
    if (gDFSHShrinePendingReward != 0) {
        obj->anim.worldPosX = obj->anim.localPosX;
        obj->anim.worldPosY = obj->anim.localPosY;
        obj->anim.worldPosZ = obj->anim.localPosZ;
        playerAddRemoveMagic(player, 0x14);
        mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
        gDFSHShrinePendingReward = 0;
    }
    GameBitLatch_UpdateInverted(&state->musicLatch, 1, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK, 8);
    GameBitLatch_Update(&state->musicLatch, 4, -1, -1, GAMEBIT_SHRINE_MUSIC_LOCK, MUSICTRIG_PU3_Adventure_c4);
    if ((f32)(s32)state->transitionTimer > 0.0f) {
        state->transitionTimer = (f32)(s32)state->transitionTimer - timeDelta;
        if ((f32)(s32)state->transitionTimer <= 0.0f) {
            state->transitionTimer = 0;
        }
        return;
    }

    switch (state->mode) {
    case DFSH_SHRINE_MODE_IDLE: {
        f32 t = state->idleChimeTimer - timeDelta;
        state->idleChimeTimer = t;
        if (t <= 0.0f) {
            Sfx_PlayFromObject((int)obj, SFXTRIG_spirit_voice);
            state->idleChimeTimer = (f32)(s32)randomGetRange(500, 1000);
        }
    }
        if ((obj->anim.resetHitboxFlags & INTERACT_FLAG_ACTIVATED) != 0) {
            mainSetBits(0x589, 0);
            state->mode = DFSH_SHRINE_MODE_BEGIN_TRANS;
            Music_Trigger(MUSICTRIG_DIM_Snow, 1);
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
        }
        break;
    case DFSH_SHRINE_MODE_BEGIN_TRANS:
        state->transitionTimer = 0x1F;
        (*gScreenTransitionInterface)->step(0x1E, SCREEN_TRANSITION_BLACK);
        state->mode = DFSH_SHRINE_MODE_AWAIT_OPEN;
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    case DFSH_SHRINE_MODE_AWAIT_OPEN:
        if (state->flags.openedBySequence == 1) {
            state->mode = DFSH_SHRINE_MODE_GRANT_REWARDS;
            mainSetBits(0xB76, 1);
            gameTimerInit(0x19, 0xD2);
            timerSetToCountUp();
        }
        break;
    case DFSH_SHRINE_MODE_GRANT_REWARDS:
        if (state->rewardIndex < 10) {
            state->rewardTimer -= timeDelta;
            if (state->rewardTimer <= 0.0f) {
                mainSetBits(DFSH_SHRINE_REWARD_BIT(state->rewardIndex), 1);
                state->rewardTimer = (f32)(u32)DFSH_SHRINE_REWARD_DELAY(state->rewardIndex);
                state->rewardIndex++;
            }
        }
        anyMissing = 0;
        for (i = 0; i < 10; i++) {
            if (mainGetBit(*(u16*)((u8*)&rewardTableCursor[0][20] + i * 2)) == 0u) {
                anyMissing = 1;
                i = 10;
            }
        }
        if (anyMissing == 0) {
            state->mode = DFSH_SHRINE_MODE_FINISH;
            state->flags.success = 1;
            gameTimerStop();
        } else if (isGameTimerDisabled() != 0) {
            state->mode = DFSH_SHRINE_MODE_FINISH;
            state->flags.success = 0;
            state->transitionTimer = 0x78;
            for (i = 0; i < 10; i++) {
                int targetId;
                void* targetObj;

                targetId = DFSH_SHRINE_TARGET_OBJECT(i);
                if (targetId != -1) {
                    targetObj = ObjList_FindObjectById(targetId);
                    if (targetObj != 0) {
                        enemy_setHealthZero((GameObject*)targetObj);
                    }
                }
            }
        }
        break;
    case DFSH_SHRINE_MODE_FINISH:
        state->mode = DFSH_SHRINE_MODE_AFTER_FINISH;
        state->transitionTimer = 0x23;
        (*gScreenTransitionInterface)->start(0x1E, SCREEN_TRANSITION_BLACK);
        break;
    case DFSH_SHRINE_MODE_AFTER_FINISH:
        state->mode = DFSH_SHRINE_MODE_POST_FINISH;
        break;
    case DFSH_SHRINE_MODE_POST_FINISH:
        if (objGetAnimStateFlags(player, 1) != 0 || mainGetBit(GAMEBIT_ITEM_TestCombatSpirit_Got) != 0u) {
            state->mode = DFSH_SHRINE_MODE_RESET;
        } else if (state->flags.success == 0) {
            state->mode = DFSH_SHRINE_MODE_RESET;
            mainSetBits(0xB70, 1);
        } else {
            state->mode = DFSH_SHRINE_MODE_RESET;
            audioStopByMask(3);
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        }
        mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
        mainSetBits(0xB76, 0);
        break;
    case DFSH_SHRINE_MODE_RESET:
        state->mode = DFSH_SHRINE_MODE_IDLE;
        state->flags.openedBySequence = 0;
        state->rewardIndex = 0;
        state->rewardTimer = 0.0f;
        mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
        mainSetBits(0xB70, 0);
        mainSetBits(0xB71, 0);
        mainSetBits(0xB76, 0);
        mainSetBits(0x589, 1);
        {
            s16 j;
            for (j = 0, required = (u16*)((u8*)rewardTableCursor[0] + 40); j < 10; j++) {
                mainSetBits(*required, 0);
                mainSetBits(*rewardTableCursor[0], 0);
                required++;
                rewardTableCursor[0]++;
            }
        }
        obj->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        break;
    }
}

void dfshShrine_init(GameObject* obj, const DFSHShrinePlacement* placement) {
    DFSHShrineState* state;

    state = obj->extra;
    obj->anim.rotX = (s16)(placement->initialYaw << 8);
    state->startDelayFrames = 0xA;
    if (placement->startDelay > 0) {
        state->startDelayFrames = (s16)((s32)placement->startDelay >> 8);
    }
    state->mode = DFSH_SHRINE_MODE_RESET;
    state->flags.openedBySequence = 0;
    state->transitionTimer = 0;
    obj->animEventCallback = dfshShrine_processAnimEvents;
    ObjMsg_AllocQueue(obj, 4);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    state->rewardIndex = 0;
    state->rewardTimer = 0.0f;
    unlockLevel(mapGetDirIdx(0x1F), 1, 0);
    if (state->light == NULL) {
        state->light = objCreateLight(NULL, 1);
    }
    obj->userData1 = 1;
    mainSetBits(GAMEBIT_MMP_EnteredKrazoaShrine, 1);
    mainSetBits(GAMEBIT_IN_KRAZOA_SHRINE, 1);
}

void dfshShrine_release(void) {
}

void dfshShrine_initialise(void) {
}
