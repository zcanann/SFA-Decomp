#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/objseq.h"
#include "main/dll/SH/SHrocketmushroom.h"
#include "main/dll/SH/SHspore.h"


extern uint GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int gameBitDecrement(int bit);
extern int gameBitIncrement(int bit);
extern void Sfx_PlayFromObject(void *obj, int id);
extern void ObjHits_DisableObject(void *obj);
extern void ObjHits_EnableObject(void *obj);
extern void *ObjHits_GetPriorityHitWithPosition(void *obj, int *hit, void *pos, int flags);
extern void *ObjHits_GetPriorityHit(void *obj, void *pos, int p3, int p4);
extern int ObjMsg_Pop(void *obj, u32 *outMessage, u32 *outSender, u32 *outParam);
extern int ObjTrigger_IsSetById(void *obj, int triggerId);
extern void objRenderFn_80041018(void *obj);
extern void Sfx_StopObjectChannel(void *obj, int channel);
extern void *Obj_GetPlayerObject(void);
extern void Obj_FreeObject(void *obj);
extern void objMove(f32 x, f32 y, f32 z, void *obj);
extern int fn_8003B500(void *obj, void *p2, f32 f1);
extern int fn_8003B228(void *obj, void *p2);
extern int characterDoEyeAnims(void *obj, void *p2);
extern void *objCreateLight(void *obj, int arg);
extern void modelLightStruct_setEnabled(void *light, int enabled, f32 scale);
extern void modelLightStruct_setLightKind(void *light, int value);
extern void modelLightStruct_setDiffuseColor(void *light, int r, int g, int b, int a);
extern void lightSetFieldBC_8001db14(void *light, int value);
extern void modelLightStruct_setDistanceAttenuation(void *light, f32 min, f32 max);
extern void ObjMsg_AllocQueue(void *obj, int count);
extern void ObjMsg_SendToObject(void *dst, int msg, void *src, void *payload);
extern void objfx_spawnDirectionalBurst(void *obj, u8 idx, u8 kind, u8 mode, u8 chance, void *origin,
                           int flags, f32 f8val, f32 mult);
extern int randomGetRange(int min, int max);
extern void bombplantspore_startDriftBurst(void *obj, void *state);
extern void bombplantspore_updateDrift(void *obj, void *state);

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern EffectInterface **gPartfxInterface;
extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 lbl_80326D98[];
extern u8 lbl_803DBFC0;
extern f64 lbl_803E53A0;
extern f32 lbl_803E5388;
extern f32 lbl_803E538C;
extern f32 lbl_803E5390;
extern f32 lbl_803E5394;
extern f32 lbl_803E53AC;
extern f32 lbl_803E53B0;
extern f32 lbl_803E53B8;
extern f32 lbl_803E53BC;
extern f32 lbl_803E53C0;
extern f32 lbl_803E53C4;
extern f32 lbl_803E53C8;
extern f64 lbl_803E53D0;
extern f64 lbl_803E53D8;
extern f32 lbl_803E53E0;
extern f32 lbl_803E53E4;
extern f32 lbl_803E53E8;
extern f32 lbl_803E53EC;
extern f32 lbl_803E53F8;
extern f32 lbl_803E53F0;
extern f32 lbl_803E53F4;

#define BOMBPLANT_GAME_BIT_AVAILABLE_SPORES 0x66c
#define BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER 0x196
#define BOMBPLANTSPORE_MSG_DETONATE 0x7000b
#define BOMBPLANTSPORE_MSG_HIT_PLAYER 0x7000a
#define BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE 0x18e
#define BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK 0x40
#define BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE 0x80
#define BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT 10
#define BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG 0x08
#define BOMBPLANTINGSPOT_READY_FLAG 0x10

void bombplantspore_update(void *obj) {
    BombPlantSporeState *state;
    s32 particleAlpha;
    s16 hitId;
    void *hitObj;
    void *playerObj;
    u32 poppedMessage;
    u32 poppedSender;
    undefined hitPosition[4];
    u32 detonateMessage;
    int i;

    state = ((GameObject *)obj)->extra;
    if ((state->stateFlags >> 6 & 1) != 0) {
        detonateMessage = BOMBPLANTSPORE_MSG_DETONATE;
        while (ObjMsg_Pop(obj, &poppedMessage, &poppedSender, NULL) != 0) {
            if (poppedMessage == detonateMessage) {
                gameBitIncrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
                Sfx_PlayFromObject(obj, SFXmv_totem_slide);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++) {
                    objfx_spawnDirectionalBurst(obj, 5, 7, 1, 0x3c, NULL, 0, lbl_803E53B0, lbl_803E53B8);
                    (*gPartfxInterface)->spawnObject(obj, 0x3f3, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
                state->detonateTimer = lbl_803E53BC;
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
                state->stateFlags &= ~BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK;
            }
        }
        if ((state->stateFlags >> 6 & 1) != 0) {
            return;
        }
    }

    if (state->detonateTimer != lbl_803E5394) {
        *(s16 *)obj += (u16)framesThisStep * 0x40;
        state->detonateTimer -= timeDelta;
        if (state->detonateTimer <= lbl_803E5394) {
            Obj_FreeObject(obj);
        }
        return;
    }

        if (state->fuseTimer < lbl_803E53C0) {
            particleAlpha = (s32)-(lbl_803E53C8 * state->fuseTimer - lbl_803E53C4);
            objfx_spawnDirectionalBurst(obj, 5, 7, 1, particleAlpha & 0xff, NULL, 0, lbl_803E53B0,
                           (f32)(lbl_803E53D8 *
                                     (double)(lbl_803E53C0 - state->fuseTimer) +
                                 lbl_803E53D0));
        }
        ObjHits_GetPriorityHit(obj, hitPosition, 0, 0);
        hitObj = **(void ***)&((GameObject *)obj)->anim.hitReactState;
        if ((state->stateFlags & 0x80) == 0) {
            state->driftTimer -= timeDelta;
            if (state->driftTimer < lbl_803E5394) {
                state->driftTimer = lbl_803E5394;
            }
            state->unk2a0 -= timeDelta;
            if (state->unk2a0 < lbl_803E5394) {
                state->unk2a0 = lbl_803E5394;
            }
            *(s16 *)obj += *(u16 *)&state->yawStep;
            ((GameObject *)obj)->anim.velocityY = lbl_803E53E0 * timeDelta + ((GameObject *)obj)->anim.velocityY;
            if (lbl_803E53E4 > ((GameObject *)obj)->anim.velocityY) {
                ((GameObject *)obj)->anim.velocityY = lbl_803E53E4;
            }
            if (((GameObject *)obj)->anim.velocityY > lbl_803E5394) {
                ((GameObject *)obj)->anim.velocityY *= lbl_803E53E8;
            }
            if (((GameObject *)obj)->anim.velocityY < lbl_803E5394) {
                ObjHits_EnableObject(obj);
            }
            bombplantspore_updateDrift(obj, state);
            if (randomGetRange(0, 100) < 5 &&
                state->driftTimer <= lbl_803E5394) {
                bombplantspore_startDriftBurst(obj, state);
            }
            state->spinTimer -= timeDelta;
            if (state->spinTimer <= lbl_803E5394) {
                state->driftSin *= lbl_803E53E8;
                state->driftCos *= lbl_803E53E8;
                state->spinTimer = lbl_803E5394;
            } else {
                state->driftSpeed =
                    lbl_803E53EC *
                        (state->driftSpeedTarget - state->driftSpeed) *
                        timeDelta +
                    state->driftSpeed;
            }
            ((GameObject *)obj)->anim.velocityX =
                state->driftSin * state->driftSpeed +
                state->driftBaseX;
            ((GameObject *)obj)->anim.velocityZ =
                state->driftCos * state->driftSpeed +
                state->driftBaseZ;
            objMove(((GameObject *)obj)->anim.velocityX * timeDelta,
                    ((GameObject *)obj)->anim.velocityY * timeDelta,
                    ((GameObject *)obj)->anim.velocityZ * timeDelta, obj);
            (*gPathControlInterface)->update(obj, (u8 *)state + 4, timeDelta);
            (*gPathControlInterface)->apply(obj, (u8 *)state + 4);
            (*gPathControlInterface)->advance(obj, (u8 *)state + 4, timeDelta);
            if (hitObj != NULL &&
                (hitId = *(s16 *)((u8 *)hitObj + 0x46), hitId != 0x36d) &&
                hitId != 0x198 && hitId != 0x63c) {
                Sfx_PlayFromObject(obj, SFXen_tiles_lightup);
                state->stateFlags =
                    state->stateFlags & ~BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE |
                    BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE;
                if (lbl_803E53C0 < state->fuseTimer) {
                    state->fuseTimer = lbl_803E53C0;
                }
            }
            if ((*(u8 *)((u8 *)state + 0x268) & 0x11) != 0) {
                state->stateFlags =
                    state->stateFlags & ~BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE |
                    BOMBPLANTSPORE_STATE_FLAG_HIT_SURFACE;
                if (lbl_803E53C0 < state->fuseTimer) {
                    state->fuseTimer = lbl_803E53C0;
                }
            }
        }
        playerObj = Obj_GetPlayerObject();
        if (hitObj == playerObj) {
            state->damageType = BOMBPLANTSPORE_PLAYER_DAMAGE_TYPE;
            ObjMsg_SendToObject(hitObj, BOMBPLANTSPORE_MSG_HIT_PLAYER, obj, state);
            state->stateFlags =
                state->stateFlags &
                    ~BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK |
                BOMBPLANTSPORE_STATE_FLAG_WAITING_FOR_DETONATE_ACK;
        } else {
            state->fuseTimer -= timeDelta;
            if (state->fuseTimer <= lbl_803E5394) {
                Sfx_PlayFromObject(obj, SFXmv_torclp_6);
                (*gExpgfxInterface)->freeSource((u32)obj);
                for (i = 0; i < BOMBPLANTSPORE_EXPLOSION_PARTICLE_COUNT; i++) {
                    objfx_spawnDirectionalBurst(obj, 5, 7, 1, 0x3c, NULL, 0, lbl_803E53B0, lbl_803E53B8);
                    (*gPartfxInterface)->spawnObject(obj, 0x3f3, NULL, 4, -1, NULL);
                }
                modelLightStruct_setEnabled(state->light, 0, lbl_803E53AC);
                state->detonateTimer = lbl_803E53BC;
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            }
    }
}

void bombplantspore_init(void *obj, void *param2) {
    BombPlantSporeState *state;
    void *light;
    f32 randomPhase;
    u32 randAsDouble[2];
    u8 events[8];

    state = ((GameObject *)obj)->extra;
    events[0] = 5;
    state->fuseTimer = lbl_803E53F0;
    ((GameObject *)obj)->objectFlags |= 0x6000;
    ((GameObject *)obj)->anim.velocityY = lbl_803E53F4;
    ObjHits_DisableObject(obj);
    state->spinAngle = (s16)randomGetRange(0, 0xffff);

    state->randomPhase = (f32)(int)randomGetRange(0, 1000) / lbl_803E5390;

    (*gPathControlInterface)->init(state->pathState, 0, 0x40002, 1);
    (*gPathControlInterface)->setup(state->pathState, 1, lbl_80326D98, &lbl_803DBFC0, events);
    (*gPathControlInterface)->attachObject(obj, state->pathState);
    (*gPartfxInterface)->spawnObject(obj, 0x3f1, NULL, 4, -1, NULL);

    light = objCreateLight(obj, 1);
    if (light != NULL) {
        modelLightStruct_setLightKind(light, 2);
        modelLightStruct_setDiffuseColor(light, 0xff, 0, 0xff, 0);
        lightSetFieldBC_8001db14(light, 1);
        modelLightStruct_setDistanceAttenuation(light, lbl_803E5388, lbl_803E538C);
    }
    state->light = light;
    ObjMsg_AllocQueue(obj, 2);
    state->yawStep = (s16)randomGetRange(-0x200, 0x200);
}

void bombplantingspot_update(void *obj) {
    BombPlantingSpotMapData *mapData = *(BombPlantingSpotMapData **)&((GameObject *)obj)->anim.placementData;
    s32 trigBit;

    *(s16 *)obj = (s16)(mapData->yawByte << 8);

    trigBit = mapData->requiredGameBit;
    if (trigBit != -1 && GameBit_Get(trigBit) == 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        return;
    }

    if (GameBit_Get(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) == 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_READY_FLAG;
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_READY_FLAG;
    }

    if (ObjTrigger_IsSetById(obj, BOMBPLANT_GAME_BIT_AVAILABLE_SPORES) != 0) {
        gameBitDecrement(BOMBPLANT_GAME_BIT_AVAILABLE_SPORES);
        GameBit_Set(mapData->plantedGameBit, 1);
        (*gObjectTriggerInterface)->runSequence(1, obj, -1);
    } else if ((*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 0x4) != 0 &&
               GameBit_Get(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER) == 0) {
        (*gObjectTriggerInterface)->runSequence(0, obj, -1);
        GameBit_Set(BOMBPLANT_GAME_BIT_FIRST_SPOT_TRIGGER, 1);
    }

    if (GameBit_Get(mapData->plantedGameBit) == 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
        objRenderFn_80041018(obj);
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= BOMBPLANTINGSPOT_MODEL_HIDDEN_FLAG;
    }
}

void bombplantingspot_init(void *obj, BombPlantingSpotMapData *mapData) {
    ((GameObject *)obj)->objectFlags |= 0x4000;
    *(s16 *)obj = (s16)(mapData->yawByte << 8);
}

int sh_queenearthwalker_processAnimEvents(void *obj, void *unused, ObjAnimUpdateState *animUpdate) {
    void *pState = ((GameObject *)obj)->extra;
    int i;
    u8 b2;

    if ((((QueenEarthWalkerState *)pState)->flags & 0x20) == 0) {
        Sfx_StopObjectChannel(obj, 0x7f);
        ((QueenEarthWalkerState *)pState)->flags &= ~0x10;
        ((QueenEarthWalkerState *)pState)->flags |= 0x20;
    }

    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (animUpdate->eventIds[i]) {
            case 0:
                ((QueenEarthWalkerState *)pState)->flags |= 0x8;
                break;
            case 1:
                ((QueenEarthWalkerState *)pState)->flags &= ~0x8;
                break;
            case 2:
                ((QueenEarthWalkerState *)pState)->flags |= 0x2;
                break;
            case 3:
                ((QueenEarthWalkerState *)pState)->flags &= ~0x2;
                animUpdate->hitVolumePair |= 0x8;
                animUpdate->hitVolumePair |= 0x40;
                break;
        }
    }

    b2 = ((QueenEarthWalkerState *)pState)->flags;
    if ((b2 & 0x2) != 0) {
        if ((b2 & 0x4) == 0) {
            void *player;
            animUpdate->hitVolumePair &= ~0x8;
            player = Obj_GetPlayerObject();
            *(u8 *)((int)pState + 0x8) = 1;
            ((QueenEarthWalkerState *)pState)->targetX = ((GameObject *)player)->anim.localPosX;
            ((QueenEarthWalkerState *)pState)->targetY = ((GameObject *)player)->anim.localPosY;
            ((QueenEarthWalkerState *)pState)->targetZ = ((GameObject *)player)->anim.localPosZ;
            fn_8003B500(obj, (u8 *)pState + 0x8, lbl_803E53F8);
        }
        animUpdate->hitVolumePair &= ~0x40;
        if ((((QueenEarthWalkerState *)pState)->flags & 0x8) != 0) {
            fn_8003B228(obj, (u8 *)pState + 0x8);
        } else {
            characterDoEyeAnims(obj, (u8 *)pState + 0x8);
        }
    }
    return 0;
}
