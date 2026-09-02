/*
 * DBstealerwo (DLL 0x242, object type id 0x49) - a burrowing "stealer
 * worm" ground baddie.
 *
 * It is a GroundBaddieState/BaddieState baddie driven through the shared
 * baddie-control interface (gBaddieControlInterface). Per-object state is
 * extraSize 0x460 = the 0x410 GroundBaddieState plus a 0x50 private
 * DbStealerwormControl record hung off GroundBaddieState.control (memset
 * to zero in dbstealerworm_init).
 *
 * Behaviour is a move/transition state machine: the A00..A0F handlers
 * (gDBStealerWormStateHandlersA, invoked from hitDetect/update) run the
 * burrow / surface / lunge / grab / steal / flee moves, while the B00..B06
 * handlers gate transitions between them. The worm surfaces and lunges at a
 * target, links to a grabbed object (DbStealerwormControl.linkedObj) via
 * ObjMsg, plays the ice-run footstep sfx, spawns burrow/impact particle fx
 * (dbstealerworm_processEffectFlags), and on a successful steal increments a placement game bit
 * and adds map time (dbstealerworm_stateHandlerA06). chuka is the linked
 * thrown sub-object.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/objfx_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/object_render.h"
#include "main/debug.h"
#include "main/dll/dll22cstate_struct.h"
#include "main/dll/dfpobjcreatorstate_struct.h"
#include "main/dll/dfptorchstate_struct.h"
#include "main/dll/dbeggstate_struct.h"
#include "main/dll/drakorenergystate_struct.h"
#include "main/dll/dbstealerwormcontrol_struct.h"
#include "main/dll/dfp_types.h"
#include "game/objects/object.h"
#include "main/mapEventTypes.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/gamebits.h"
#include "main/gameloop_gamebit_api.h"
#include "main/frame_timing.h"
#include "main/objhits.h"
#include "main/player_control_interface.h"
#include "main/objprint_api.h"
#include "main/vecmath.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/dll_0242_dbstealerworm.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/baddie_control_interface.h"

extern int gDbStealerwormRunToAvoidGroups[];
extern f32 gDbStealerwormRunToAvoidWeights[];
extern int gDbStealerwormWaitAvoidGroups[];
extern f32 gDbStealerwormWaitAvoidWeights[];
extern int gDbStealerwormKillAvoidGroups[];
extern f32 gDbStealerwormKillAvoidWeights[];

typedef struct {
    int* msgs; /* 0x00 */
    s16 count; /* 0x04 */
    u8 pad06[0x08 - 0x06];
} DbWormMsgGroup;

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);
extern DbStealerwormScript gDbStealerwormScriptTable[];

int dbstealerworm_turnToFaceObject(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused,
                                   f32 range);
int dbstealerworm_turnToFaceObjectVertical(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused,
                                           f32 range);
int dbstealerworm_avoidObjects(GameObject* obj, int* objs, f32* weights, int n, f32 limit);

static void dbstealerworm_restartMove(GameObject* obj, BaddieState* baddie) {
    if (baddie->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0x11, 0.0f, 0);
        baddie->moveDone = 0;
    }
}

int dbstealerworm_stateHandlerB06(GameObject* obj, BaddieState* baddie) {

    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub;
    GroundBaddiePlacement* data = (GroundBaddiePlacement*)(obj)->anim.placementData;
    int count;
    const DbStealerwormScript* entry;
    char* ptr;
    f32 range;

    range = 1500.0f;
    sub = (DbStealerwormControl*)state->control;
    if (baddie->moveJustStartedB != 0 || sub->advanceMessage != 0) {
        sub->flags15 &= ~4;
        sub->advanceMessage = 0;
        if (Stack_IsEmpty(sub->messageStack) == 0) {
            Stack_Pop(sub->messageStack, &sub->messageCode);
        } else {
            if (data->base.ident == 0xFFFFFFFF) {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = &gDbStealerwormScriptTable[data->unk24];
            count = entry->stepCount;
            for (; count != 0;) {
                Stack_Push(sub->messageStack, (int*)&entry->steps[--count]);
            }
            sub->advanceMessage = 1;
            (obj)->anim.localPosX = data->base.posX;
            (obj)->anim.localPosY = data->base.posY;
            (obj)->anim.localPosZ = data->base.posZ;
        }
        switch (sub->messageMode) {
        case 0:
            if (sub->messageObjGroup != 0) {
                baddie->targetObj = objGetNearestTypeToExcludingSelf(sub->messageObjGroup, obj, &range);
            }
            break;
        case 1:
            baddie->targetObj = (void*)sub->messageObjGroup;
            break;
        }
        if (baddie->targetObj != NULL) {
            (*gPlayerInterface)->setState(obj, baddie, sub->messageCode);
        }
        return 0;
    } else {
        switch (sub->messageMode) {
        case 0:
            if (baddie->targetObj == NULL) {
                sub->advanceMessage = 1;
            } else if (sub->messageObjGroup != 0) {
                if (objIsObjectType(baddie->targetObj, sub->messageObjGroup) == 0) {
                    baddie->targetObj = objGetNearestTypeToExcludingSelf(sub->messageObjGroup, obj, 0);
                    if (baddie->targetObj == NULL) {
                        sub->advanceMessage = 1;
                    }
                    baddie->animSpeedA = 0.0f;
                }
            }
            break;
        case 1:
            if (baddie->targetObj == NULL) {
                sub->advanceMessage = 1;
            }
            break;
        }
        if (sub->heldScriptSlot == -1 && (ptr = (char*)sub->savedTargetObj) != NULL) {
            if (DB_STEALERWORM_INTERFACE(ptr)->getControlMode((GameObject*)ptr) == 0) {
                sub->savedTargetObj = 0;
                sub->advanceMessage = 1;
            }
        }
        return 0;
    }
}

int dbstealerworm_stateHandlerB05(GameObject* obj, BaddieState* baddie) {
    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub;
    GroundBaddiePlacement* data = (GroundBaddiePlacement*)(obj)->anim.placementData;
    const DbStealerwormScript* base;
    int routeIndex;
    GameObject* found;
    int i;
    int* p;
    GameObject* nearest;
    int buf[3];
    f32 range;

    range = 1500.0f;
    sub = (DbStealerwormControl*)state->control;
    if (baddie->moveJustStartedB != 0 || sub->flags44.flag40 != 0) {
        sub->flags15 &= ~4;
        sub->flags44.flag40 = 0;
        if (Stack_IsEmpty(sub->messageStack) == 0) {
            Stack_Pop(sub->messageStack, buf);
        }
        base = sub->script;
        routeIndex = sub->scriptCursor - base->steps;
        if (routeIndex >= base->stepCount) {
            sub->scriptCursor = NULL;
        }
        if (sub->scriptCursor == NULL) {
            sub->scriptCursor = sub->script->steps;
            (obj)->anim.localPosX = data->base.posX;
            (obj)->anim.localPosY = data->base.posY;
            (obj)->anim.localPosZ = data->base.posZ;
        }
        if (sub->scriptCursor->mode != 0) {
            baddie->targetObj = objGetNearestTypeToExcludingSelf(sub->scriptCursor->mode, obj, &range);
        }
        if (baddie->targetObj != NULL) {
            (*gPlayerInterface)->setState(obj, baddie, sub->scriptCursor->code);
        }
        return 0;
    } else {
        f32 t;
        if (sub->linkedObject == NULL && (t = sub->spawnAccumulator) > 100.0f) {
            sub->spawnAccumulator = t - 100.0f;
            range = 200.0f;
            i = 3;
            found = 0;
            p = &gDbStealerwormRunToAvoidGroups[3];
            for (; (p--, --i) >= 0;) {
                nearest = objGetNearestTypeToExcludingSelf(*p, obj, &range);
                if (nearest != 0) {
                    found = nearest;
                }
            }
            baddie->targetObj = found;
            if (found != 0) {
                if (range < 50.0f) {
                    (*gPlayerInterface)->setState(obj, baddie, 2);
                } else {
                    (*gPlayerInterface)->setState(obj, baddie, 4);
                }
            }
        }
    }
    return 0;
}

#define DBSTEALERWORM_OBJGROUP 3
#define DBEGG_OBJGROUP         0x24

/* projectile spat at the baddie target: velocity aimed at targetObj, ownerObj = worm */
#define DBSTEALERWORM_SEQID                    0x539 /* retail "DBstealerwo..." (DLL 0x242) */
#define DBSTEALERWORM_CHILD_OBJ_ICE_BALL_SMALL 0x30a

static inline void dbstealerworm_queueMessage(RingBufferQueue* messageQueue, int code, int mode, int objGroup) {
    DbStealerwormMessageFrame message;

    message.code = code;
    message.mode = mode;
    message.objGroup = objGroup;
    if (Stack_IsFull(messageQueue) == 0) {
        Stack_Push(messageQueue, &message);
    }
}

static inline void dbstealerworm_updateTurnSpeed(BaddieState* state, s16 yaw, f32 speed) {
    f32 smoothing;
    f32 currentSpeed;
    f32 targetSpeed;

    currentSpeed = state->animSpeedA;
    smoothing = timeDelta / 4.0f;
    targetSpeed = speed * (1.0f - (f32)yaw / 65536.0f);
    state->animSpeedA = smoothing * (targetSpeed - currentSpeed) + currentSpeed;
    state->animSpeedB = 0.0f;
}

/* small dust burst (spawned 3x when DBWORM_FLAG14_FX_DUST is set) */
#define DBSTEALERWORM_PARTFX_DUST 0x345
/* spray burst (spawned 10x when DBWORM_FLAG14_FX_SPRAY is set) */
#define DBSTEALERWORM_PARTFX_SPRAY 0x343

/* hit-volume slot reconfigured across the worm's movement states */
#define DBSTEALERWORM_HIT_VOLUME_SLOT 10

/* fx-spawn work record: a fake ObjAnimComponent head handed to
 * objDoHitParticleFx / the partfx interface (same family as ktrex's
 * gKTRexEffectSpawnWork). */
typedef struct DbWormEffectSpawnWork {
    s16 rotX; /* 0x00 */
    s16 rotY;
    s16 rotZ;
    u8 pad6[2];
    f32 scale; /* 0x08 */
    f32 posX;  /* 0x0C: fx spawn position */
    f32 posY;
    f32 posZ;
} DbWormEffectSpawnWork;

STATIC_ASSERT(sizeof(DbWormEffectSpawnWork) == 0x18);

DbWormEffectSpawnWork gDbWormEffectSpawnWork;
void* gDBStealerWormStateHandlersB[7];

extern int gDbStealerwormDeathFootstepSfx[];
extern int gDbStealerwormBurrowFootstepSfx[];
extern int gDbStealerwormSfxIds[];
extern DbStealerwormScriptStep gDbStealerwormScriptStealEggThrowToWorm[];

int dbstealerworm_stateHandlerB04(GameObject* obj, BaddieState* baddie) {
    float fz;
    GroundBaddieState* state;
    DbStealerwormControl* control;

    state = obj->extra;
    if (baddie->moveJustStartedB != 0) {
        (*gPlayerInterface)->setState(obj, baddie, 1);
        control = state->control;
        fz = 0.0f;
        control->countdown = 0.0f;
        control->nextSfxTime = fz;
        control->unk04 = fz;
    }
    return 0;
}

int dbstealerworm_stateHandlerB03(GameObject* obj, BaddieState* baddie) {
    GroundBaddieState* state = obj->extra;
    if (baddie->moveJustStartedB != 0) {
        (*gBaddieControlInterface)->spawnChild(obj, state->triggerId, -1, 0);
    }
    return 0;
}

int dbstealerworm_stateHandlerB02(GameObject* obj, BaddieState* baddie) {
    GroundBaddieState* state;
    DbStealerwormControl* control;
    float fz;
    s8 flag2;

    state = obj->extra;
    if (baddie->moveJustStartedB != 0) {
        control = state->control;
        fz = 0.0f;
        control->countdown = 0.0f;
        control->nextSfxTime = fz;
        control->unk04 = fz;
        (*gPlayerInterface)->setState(obj, baddie, 6);
    } else {
        flag2 = baddie->moveDone;
        if (flag2 != 0) {
            if (obj->anim.alpha == 0) {
                if (flag2 != 0) {
                    return 7;
                }
            }
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerB01(GameObject* obj, BaddieState* baddie) {
    GroundBaddieState* state = obj->extra;
    if (baddie->hitPoints < 1) {
        return 3;
    }
    if (baddie->moveDone != 0) {
        ((DbStealerwormControl*)state->control)->spawnAccumulator += 170.0f;
        return 7;
    }
    return 0;
}

int dbstealerworm_stateHandlerB00(GameObject* obj, BaddieState* baddie) {
    BaddieState* p = baddie;
    f32 fz;
    if (p->targetObj != NULL) {
        if (p->moveJustStartedB != 0) {
            fz = 0.0f;
            p->animSpeedB = fz;
            p->animSpeedA = fz;
            return 7;
        }
        if (p->moveDone != 0) {
            return 7;
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA0F(GameObject* obj, BaddieState* baddie, f32 t) {
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int n = 0x1f40 / blob->aggression;
    int tmpB;
    int tmpA;
    int tmpD;
    int tmpC;
    f32 frac;
    f32 d;
    f32 k;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    if (((GameObject*)((BaddieState*)baddie)->targetObj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) {
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = 0.0f;
        ((BaddieState*)baddie)->moveSpeed = 0.001f;
        return 0;
    }
    frac = blob->aggression / 40.0f;
    dbstealerworm_turnToFaceObject(obj, ((BaddieState*)baddie)->targetObj, 1.0f, frac, 0.2f, t);
    if (sub->flags44.flag20 != 0) {
        dbstealerworm_avoidObjects(obj, gDbStealerwormKillAvoidGroups, gDbStealerwormKillAvoidWeights, 4, frac);
    }
    d = Vec_xzDistance(&obj->anim.worldPosX, &((GameObject*)((BaddieState*)baddie)->targetObj)->anim.worldPosX);
    ((BaddieState*)baddie)->stateTag = 1;
    if (d < 30.0f) {
        ((BaddieState*)baddie)->animSpeedA = ((BaddieState*)baddie)->animSpeedA * (k = 0.5f);
        ((BaddieState*)baddie)->animSpeedB *= k;
        obj = (GameObject*)((BaddieState*)baddie)->targetObj;
        tmpA = sub->messageObjGroup;
        tmpB = sub->messageMode;
        baddie = (BaddieState*)sub->messageStack;
        msgA[0] = sub->messageCode;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0) {
            Stack_Push((RingBufferQueue*)baddie, msgA);
        }
        baddie = (BaddieState*)sub->messageStack;
        msgB[0] = 2;
        msgB[1] = 1;
        msgB[2] = (int)obj;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0) {
            Stack_Push((RingBufferQueue*)baddie, msgB);
        }
        sub->advanceMessage = 1;
        return 0;
    }
    if (d < 150.0f && randomGetRange(0, n) == 0) {
        ((BaddieState*)baddie)->animSpeedB = ((BaddieState*)baddie)->animSpeedA = 0.0f;
        obj = (GameObject*)((BaddieState*)baddie)->targetObj;
        tmpC = sub->messageObjGroup;
        tmpD = sub->messageMode;
        baddie = (BaddieState*)sub->messageStack;
        msgC[0] = sub->messageCode;
        msgC[1] = tmpD;
        msgC[2] = tmpC;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0) {
            Stack_Push((RingBufferQueue*)baddie, msgC);
        }
        baddie = (BaddieState*)sub->messageStack;
        msgD[0] = 4;
        msgD[1] = 1;
        msgD[2] = (int)obj;
        if (Stack_IsFull((RingBufferQueue*)baddie) == 0) {
            Stack_Push((RingBufferQueue*)baddie, msgD);
        }
        sub->advanceMessage = 1;
        return 0;
    }
    ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj, ((BaddieState*)baddie)->animSpeedA,
                                 &((BaddieState*)baddie)->moveSpeed);
    return 0;
}

int dbstealerworm_stateHandlerA0E(GameObject* obj, BaddieState* baddie) {
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    BaddieState* bs = baddie;
    sub->flags14 = sub->flags14 | DBWORM_FLAG14_FX_DUST;
    sub->flags15 = sub->flags15 | 0x4;
    bs->moveSpeed = 0.02f;
    dbstealerworm_restartMove(obj, bs);
    bs->stateTag = 0x1f;
    if (bs->moveJustStartedA != 0) {
        sub->linkedObject = bs->targetObj;
        sub->heldScriptSlot = 0x24;
        sub->messageMode = 0;
        ObjMsg_SendToObject(sub->linkedObject, 0x11, obj, 0x12);
        Sfx_PlayFromObject(obj, SFXTRIG_mn_dimspit6);
    }
    if ((obj)->anim.currentMoveProgress > 0.3f) {
        sub->advanceMessage = 1;
    }
    return 0;
}
int dbstealerworm_stateHandlerA0D(GameObject* obj, BaddieState* baddie) {
    DbStealerwormControl* sub = (DbStealerwormControl*)(*(GroundBaddieState**)&obj->extra)->control;
    BaddieState* bs = baddie;
    int targetObj;
    f32 v;
    f32 d;
    f32 posBuf[3];
    f32* pos = posBuf;
    int msg9[3];
    int msg7[3];
    int msgE[3];

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    v = bs->animSpeedA;
    d = 1.5f;
    bs->animSpeedA = v / d;
    bs->animSpeedB = bs->animSpeedB / d;
    bs->moveSpeed = 0.01f;
    dbstealerworm_restartMove(obj, bs);
    bs->stateTag = 0x1f;
    if (obj->anim.currentMoveProgress > 0.3f &&
        ((GameObject*)bs->targetObj)->anim.localPosY - 5.0f <= obj->anim.localPosY) {
        obj = (GameObject*)sub->messageStack;
        msg9[0] = 9;
        msg9[1] = 0;
        msg9[2] = 0x24;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0) {
            Stack_Push((RingBufferQueue*)obj, msg9);
        }
        sub->advanceMessage = 1;
        targetObj = (int)bs->targetObj;
        obj = (GameObject*)sub->messageStack;
        msg7[0] = 7;
        msg7[1] = 1;
        msg7[2] = targetObj;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0) {
            Stack_Push((RingBufferQueue*)obj, msg7);
        }
        sub->advanceMessage = 1;
        return 0;
    } else {
        pos[0] = obj->anim.localPosX;
        pos[1] = obj->anim.localPosY;
        pos[2] = obj->anim.localPosZ;
        pos[1] += 20.0f;
        pos[0] = ((GameObject*)bs->targetObj)->anim.localPosX - pos[0];
        pos[1] = ((GameObject*)bs->targetObj)->anim.localPosY - pos[1];
        pos[2] = ((GameObject*)bs->targetObj)->anim.localPosZ - pos[2];
        if (sqrtf(pos[2] * pos[2] + (pos[0] * pos[0] + pos[1] * pos[1])) < 50.0f) {
            targetObj = (int)bs->targetObj;
            obj = (GameObject*)sub->messageStack;
            msgE[0] = 0xe;
            msgE[1] = 1;
            msgE[2] = targetObj;
            if (Stack_IsFull((RingBufferQueue*)obj) == 0) {
                Stack_Push((RingBufferQueue*)obj, msgE);
            }
            sub->advanceMessage = 1;
        }
    }
    return 0;
}
int dbstealerworm_stateHandlerA0C(GameObject* obj, BaddieState* baddie, f32 t) {
    char* tbl = (char*)gDbStealerwormScriptStealEggThrowToWorm;
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int c30 = sub->messageObjGroup;
    s16 h;
    int n;
    int q;
    GameObject** objs;
    int best;
    GameObject* player;
    GameObject* o;
    GameObject** cursor;
    int i;
    int tmpB;
    int tmpA;
    f32 bestD;
    f32 frac;
    f32 ratio;
    f32 ds;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int cnt;

    sub->flags15 &= ~4;
    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    logPrintf(tbl + 0x430, sub->savedTargetObj, sub->linkedObj);
    if (sub->savedTargetObject == NULL) {
        player = Obj_GetPlayerObject();
        obj = (GameObject*)sub->messageStack;
        msg0[0] = 0xf;
        msg0[1] = 1;
        msg0[2] = (int)player;
        if (Stack_IsFull((RingBufferQueue*)obj) == 0) {
            Stack_Push((RingBufferQueue*)obj, msg0);
        }
        sub->advanceMessage = 1;
        return 0;
    }
    dbstealerworm_restartMove(obj, baddie);
    baddie->moveSpeed = 0.018f;
    frac = blob->aggression / 50.0f;
    if (sub->linkedObject == NULL) {
        h = sub->heldScriptSlot;
        if (h != -1) {
            tmpA = sub->messageObjGroup;
            tmpB = sub->messageMode;
            q = (int)sub->messageStack;
            msgA[0] = sub->messageCode;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull((RingBufferQueue*)q) == 0) {
                Stack_Push((RingBufferQueue*)q, msgA);
            }
            q = (int)sub->messageStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull((RingBufferQueue*)q) == 0) {
                Stack_Push((RingBufferQueue*)q, msgB);
            }
            sub->advanceMessage = 1;
            sub->heldScriptSlot = -1;
        }
    }
    if (sub->flags44.flag20 != 0) {
        dbstealerworm_avoidObjects(obj, (int*)(tbl + 0x344), (f32*)(tbl + 0x354), 4, frac);
    }
    player = Obj_GetPlayerObject();
    ratio = (Vec_xzDistance(&obj->anim.worldPosX, &player->anim.worldPosX) - 60.0f) / (0.05f * blob->aggression);
    n = (int)(ratio < 0.0f ? 0.0f : (ratio > 100.0f ? 100.0f : ratio));
    logPrintf(tbl + 0x444, n);
    player = Obj_GetPlayerObject();
    best = 0;
    bestD = 0.0f;
    objs = objGetAllOfType(c30, &cnt);
    for (i = 0, cursor = objs; i < cnt; i++) {
        o = (GameObject*)*cursor;
        if ((u32)o != (u32)player) {
            ds = vec3f_distanceSquared(&player->anim.worldPosX, &o->anim.worldPosX);
            if (ds > bestD) {
                bestD = ds;
                best = (int)*cursor;
            }
        }
        cursor++;
    }
    if ((u32)best != 0) {
        sqrtf(bestD);
    }
    if ((u32)best != 0) {
        if ((u32)best != (u32)obj) {
            if (((GameObject*)best)->anim.romDefNo == DBSTEALERWORM_SEQID) {
                baddie->targetObj = (void*)best;
                if (randomGetRange(0, n) == 0) {
                    if (DB_STEALERWORM_INTERFACE(best)->handleMessage((GameObject*)best, 0x82, (int*)sub->linkedObj) !=
                        0) {
                        sub->savedTargetObj = 0;
                        objs = (GameObject**)sub->messageStack;
                        msgC[0] = 0xa;
                        msgC[1] = 1;
                        msgC[2] = best;
                        if (Stack_IsFull((RingBufferQueue*)objs) == 0) {
                            Stack_Push((RingBufferQueue*)objs, msgC);
                        }
                        sub->advanceMessage = 1;
                    }
                } else {
                    dbstealerworm_turnToFaceObject(obj, (GameObject*)best, 204.0f, frac, 0.2f, t);
                }
            }
        }
    }
    return 0;
}

int dbstealerworm_stateHandlerA0B(GameObject* obj, BaddieState* baddie, f32 t) {
    DbStealerwormControl* control;
    GroundBaddieState* groundState = obj->extra;
    int messageObjGroup;
    GameObject* claimedTarget;
    int targetClaimed;
    int objectIndex;
    GameObject* targetObject;
    int jointIndex;
    RingBufferQueue* waitQueue;
    RingBufferQueue* claimQueue;
    RingBufferQueue* claimHoldQueue;
    RingBufferQueue* claimScriptQueue;
    RingBufferQueue* claimTargetQueue;
    RingBufferQueue* trackQueue;
    RingBufferQueue* trackHoldQueue;
    RingBufferQueue* trackTargetQueue;
    RingBufferQueue* faceQueue;
    RingBufferQueue* faceIdleQueue;
    GameObject** objects;
    GameObject* player;
    s16 playerYawDelta;
    int facingPlayer;
    GameObject** objectList;
    int* jointKeys;
    Vec3s* jointRotation;
    f32 turnSpeed;
    int objectCount;
    int wormCount;
    f32 playerYaw;

    control = (DbStealerwormControl*)groundState->control;
    messageObjGroup = control->messageObjGroup;
    control->flags14 |= DBWORM_FLAG14_FX_DUST;
    control->flags15 &= ~4;
    if (objIsObjectType(baddie->targetObj, messageObjGroup) == 0) {
        objGetAllOfType(messageObjGroup, &objectCount);
        if (objectCount == 0) {
            player = Obj_GetPlayerObject();
            waitQueue = control->messageStack;
            dbstealerworm_queueMessage(waitQueue, 0xf, 1, (int)player);
            control->advanceMessage = 1;
            return 0;
        }
    }
    targetObject = baddie->targetObj;
    targetClaimed = 0;
    objectList = (GameObject**)objGetAllOfType(DBSTEALERWORM_OBJGROUP, &wormCount);
    for (objectIndex = 0, objects = objectList; objectIndex < wormCount; objectIndex++) {
        if ((*objects)->anim.romDefNo == DBSTEALERWORM_SEQID) {
            claimedTarget = (GameObject*)DB_STEALERWORM_INTERFACE(*objects)->handleMessage(*objects, 0x83, NULL);
            if (claimedTarget == targetObject) {
                targetClaimed = 1;
            }
        }
        objects++;
    }
    if (targetClaimed == 0 && obj == objGetNearestTypeTo(DBSTEALERWORM_OBJGROUP, baddie->targetObj, 0)) {
        int messageMode;
        int messageArg;
        int savedTarget;

        control->savedTargetObj = (int)baddie->targetObj;
        messageArg = control->messageObjGroup;
        messageMode = control->messageMode;
        claimQueue = control->messageStack;
        dbstealerworm_queueMessage(claimQueue, control->messageCode, messageMode, messageArg);
        claimHoldQueue = control->messageStack;
        dbstealerworm_queueMessage(claimHoldQueue, 0xc, 0, 3);
        control->advanceMessage = 1;
        claimScriptQueue = control->messageStack;
        dbstealerworm_queueMessage(claimScriptQueue, 9, 0, messageObjGroup);
        control->advanceMessage = 1;
        savedTarget = control->savedTargetObj;
        claimTargetQueue = control->messageStack;
        dbstealerworm_queueMessage(claimTargetQueue, 7, 1, savedTarget);
        control->advanceMessage = 1;
        return 0;
    }
    control = (DbStealerwormControl*)groundState->control;
    baddie->stateTag = 0x1f;
    if (baddie->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xf, 0.0f, 0);
        baddie->moveDone = 0;
    }
    if (control->savedTargetObject != NULL && objIsObjectType(baddie->targetObj, messageObjGroup) != 0) {
        int messageMode;
        int messageArg;
        int savedTarget;

        messageArg = control->messageObjGroup;
        messageMode = control->messageMode;
        trackQueue = control->messageStack;
        dbstealerworm_queueMessage(trackQueue, control->messageCode, messageMode, messageArg);
        trackHoldQueue = control->messageStack;
        dbstealerworm_queueMessage(trackHoldQueue, 0xc, 0, 3);
        control->advanceMessage = 1;
        savedTarget = control->savedTargetObj;
        trackTargetQueue = control->messageStack;
        dbstealerworm_queueMessage(trackTargetQueue, 0xd, 1, savedTarget);
        control->advanceMessage = 1;
        return 0;
    }
    turnSpeed = groundState->aggression / 40.0f;
    dbstealerworm_turnToFaceObject(obj, baddie->targetObj, 200.0f, turnSpeed, 0.2f, t);
    if (control->flags44.flag20 != 0) {
        dbstealerworm_avoidObjects(obj, gDbStealerwormWaitAvoidGroups, gDbStealerwormWaitAvoidWeights, 4, turnSpeed);
    }
    player = Obj_GetPlayerObject();
    playerYawDelta = Obj_GetYawDeltaToObject(obj, player, &playerYaw);
    facingPlayer = 0;
    if ((playerYawDelta >= 0 ? playerYawDelta : -playerYawDelta) < 0x1c71 && playerYaw < 30.0f) {
        facingPlayer = 1;
    }
    if (facingPlayer != 0) {
        int messageMode;
        int messageArg;

        jointKeys = objGetLookAtJointKeys();
        for (jointIndex = 1, jointKeys++; jointIndex < 9; jointKeys++, jointIndex++) {
            jointRotation = (Vec3s*)objFindJointPoseVector(obj, *jointKeys);
            if (jointRotation != NULL) {
                jointRotation->z = 0;
                jointRotation->x = 0;
            }
        }
        player = Obj_GetPlayerObject();
        baddie->targetObj = player;
        messageArg = control->messageObjGroup;
        messageMode = control->messageMode;
        faceQueue = control->messageStack;
        dbstealerworm_queueMessage(faceQueue, control->messageCode, messageMode, messageArg);
        faceIdleQueue = control->messageStack;
        dbstealerworm_queueMessage(faceIdleQueue, 2, 0, 0);
        control->advanceMessage = 1;
    }
    return 0;
}
int dbstealerworm_stateHandlerA0A(GameObject* obj, BaddieState* state) {
    GroundBaddieState* groundState = obj->extra;
    DbStealerwormControl* control = groundState->control;
    RingBufferQueue* messageQueue;
    int objGroup = control->messageObjGroup;
    int messageMode = control->messageMode;
    int currentMsgMode;
    int messageArg;
    GameObject* targetObject;
    f32 zero;
    f32 horizontalDistance;
    f32 launchVelocity[3];
    f32 targetOffsetBuffer[3];
    f32* targetOffset = targetOffsetBuffer;
    int currentMessage[3];
    int resumeMessage[3];
    int unlinkMessage[3];

    zero = 0.0f;
    state->animSpeedA = 0.0f;
    state->animSpeedB = zero;
    control->flags14 |= DBWORM_FLAG14_FX_DUST;
    if (control->linkedObject == NULL && control->heldScriptSlot != -1) {
        messageArg = control->messageObjGroup;
        currentMsgMode = control->messageMode;
        messageQueue = control->messageStack;
        currentMessage[0] = control->messageCode;
        currentMessage[1] = currentMsgMode;
        currentMessage[2] = messageArg;
        if (Stack_IsFull(messageQueue) == 0) {
            Stack_Push(messageQueue, currentMessage);
        }
        messageQueue = control->messageStack;
        resumeMessage[0] = 8;
        resumeMessage[1] = messageMode;
        resumeMessage[2] = objGroup;
        if (Stack_IsFull(messageQueue) == 0) {
            Stack_Push(messageQueue, resumeMessage);
        }
        control->advanceMessage = 1;
        messageArg = control->heldScriptSlot;
        messageQueue = control->messageStack;
        unlinkMessage[0] = 9;
        unlinkMessage[1] = 0;
        unlinkMessage[2] = messageArg;
        if (Stack_IsFull(messageQueue) == 0) {
            Stack_Push(messageQueue, unlinkMessage);
        }
        control->advanceMessage = 1;
        return 0;
    } else {
        control->flags15 |= 4;
        if (control->linkedObject != NULL && (s32)(state->eventFlags & BADDIE_EVENT_LANDING) != 0) {
            targetObject = state->targetObj;
            targetOffset[0] = targetObject->anim.localPosX - obj->anim.localPosX;
            targetOffset[1] = targetObject->anim.localPosY - obj->anim.localPosY;
            targetOffset[2] = targetObject->anim.localPosZ - obj->anim.localPosZ;
            {
                f32 squaredX = targetOffset[0] * targetOffset[0];
                f32 squaredZ = targetOffset[2] * targetOffset[2];
                horizontalDistance = sqrtf(squaredX + squaredZ);
            }
            targetOffset[1] *= 0.015625f;
            horizontalDistance = horizontalDistance / 140.0f;
            launchVelocity[1] =
                -(horizontalDistance * (-1.7f * horizontalDistance) - targetOffset[1]) / horizontalDistance;
            launchVelocity[1] *= 1.0666667f;
            launchVelocity[0] = 0.0f;
            launchVelocity[2] = 2.3333333f;
            ObjMsg_SendToObject(control->linkedObject, 0x11, obj, 0x11);
            ((void (*)(GameObject*, f32*))control->linkedObject->anim.dll[0][9])(control->linkedObject, launchVelocity);
            control->linkedObject = NULL;
            control->heldScriptSlot = -1;
        }
        obj->anim.rotX += Obj_GetYawDeltaToObject(obj, state->targetObj, NULL);
        state->stateTag = 0x11;
        if (state->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x12, 0.0f, 0);
            state->moveDone = 0;
        }
        if (state->moveDone != 0) {
            control->advanceMessage = 1;
        }
        return 0;
    }
}

int dbstealerworm_stateHandlerA09(GameObject* obj, BaddieState* baddie) {
    BaddieState* bs = baddie;
    DbStealerwormControl* control;
    int slotIndex;
    int frame[3];
    int frame2[3];
    f32 resetValue;

    control = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    slotIndex = control->messageObjGroup;
    control->flags14 |= DBWORM_FLAG14_FX_DUST;
    resetValue = 0.0f;
    bs->animSpeedA = resetValue;
    bs->animSpeedB = resetValue;
    {
        void* p2d0 = bs->targetObj;
        if (p2d0 == NULL || DB_STEALERWORM_INTERFACE(p2d0)->getControlMode((GameObject*)p2d0) == 0) {
            control->advanceMessage = 1;
        }
    }
    if (control->linkedObject == NULL) {
        s16 heldScriptSlot = control->heldScriptSlot;
        if (heldScriptSlot != -1) {
            RingBufferQueue* messageStack;
            int messageMode;
            int objGroup;
            objGroup = control->messageObjGroup;
            messageMode = control->messageMode;
            messageStack = control->messageStack;
            frame[0] = control->messageCode;
            frame[1] = messageMode;
            frame[2] = objGroup;
            if (Stack_IsFull(messageStack) == 0) {
                Stack_Push(messageStack, frame);
            }
            messageStack = control->messageStack;
            frame2[0] = 7;
            frame2[1] = 0;
            frame2[2] = heldScriptSlot;
            if (Stack_IsFull(messageStack) == 0) {
                Stack_Push(messageStack, frame2);
            }
            control->advanceMessage = 1;
            control->heldScriptSlot = -1;
        }
    }
    if ((s32)(bs->eventFlags & BADDIE_EVENT_LANDING) != 0) {
        control->linkedObject = bs->targetObj;
        control->heldScriptSlot = slotIndex;
        control->messageMode = 0;
        ObjMsg_SendToObject(control->linkedObject, 17, obj, 18);
        Sfx_PlayFromObject(obj, SFXTRIG_mn_dimspit6);
    }
    bs->stateTag = 18;
    if (bs->moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove(obj, 16, 0.0f, 0);
        bs->moveDone = 0;
    }
    if (bs->moveDone != 0) {
        control->advanceMessage = 1;
    }
    return 0;
}
int dbstealerworm_stateHandlerA08(GameObject* obj, BaddieState* baddie, f32 t) {
    int q;
    int* ptr;
    int* p2;
    int i2;
    int* p3;
    int i3;
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    int tmpB;
    s16 h;
    int tmpA;
    int tmp2B;
    int tmp2A;
    GameObject* player;
    int flag;
    s16 d;
    int zero;
    Vec3s* jointRotation;
    s16 sa;
    s16 sb;
    f32 frac;
    f32 yawf;

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    if (baddie->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    }
    baddie->moveSpeed = 0.01f;
    if (sub->linkedObject == NULL) {
        h = sub->heldScriptSlot;
        if (h != -1) {
            tmpA = sub->messageObjGroup;
            tmpB = sub->messageMode;
            q = (int)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)q, sub->messageCode, tmpB, tmpA);
            q = (int)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)q, 9, 0, h);
            sub->advanceMessage = 1;
            sub->heldScriptSlot = -1;
        }
    } else {
        if (baddie->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, 0.0f, 0);
            baddie->moveDone = 0;
        }
        baddie->moveSpeed = 0.018f;
        frac = blob->aggression / 80.0f;
    }
    baddie->stateTag = 0x1f;
    if (dbstealerworm_turnToFaceObject(obj, baddie->targetObj, 200.0f, frac, 0.2f, t) != 0) {
        sub->advanceMessage = 1;
    }
    if (sub->flags44.flag20 != 0) {
        dbstealerworm_avoidObjects(obj, gDbStealerwormRunToAvoidGroups, gDbStealerwormRunToAvoidWeights, 4, frac);
    } else if (sub->linkedObject == NULL) {
        player = Obj_GetPlayerObject();
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if ((d >= 0 ? d : -d) < 0x1c71 && yawf < 30.0f) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = objGetLookAtJointKeys();
            zero = 0;
            for (q = 1, ptr = ptr + 1; q < 9; ptr++, q++) {
                jointRotation = (Vec3s*)objFindJointPoseVector(obj, *ptr);
                if (jointRotation != NULL) {
                    jointRotation->z = zero;
                    jointRotation->x = zero;
                }
            }
            player = Obj_GetPlayerObject();
            baddie->targetObj = player;
            tmp2A = sub->messageObjGroup;
            tmp2B = sub->messageMode;
            ptr = (int*)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)ptr, sub->messageCode, tmp2B, tmp2A);
            ptr = (int*)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)ptr, 2, 0, 0);
            sub->advanceMessage = 1;
        }
    }
    if (sub->flags44.flag40 != 0) {
        p2 = objGetLookAtJointKeys();
        zero = 0;
        for (i2 = 1, p2 = p2 + 1; i2 < 9; p2++, i2++) {
            jointRotation = (Vec3s*)objFindJointPoseVector(obj, *p2);
            if (jointRotation != NULL) {
                jointRotation->z = zero;
                jointRotation->x = zero;
            }
        }
    } else if (sub->linkedObject == NULL) {
        int dv = -(2535.0f * baddie->animSpeedA);
        int fv = -(2535.0f * baddie->animSpeedB);
        dv = (s16)dv;
        if (dv < -0x500) {
            dv = -0x500;
        } else if (dv > 0x500) {
            dv = 0x500;
        }
        sa = dv;
        fv = (s16)fv;
        if (fv < -0x500) {
            fv = -0x500;
        } else if (fv > 0x500) {
            fv = 0x500;
        }
        sb = fv;
        p3 = objGetLookAtJointKeys();
        i3 = 1;
        p3 = p3 + 1;
        for (; i3 < 9; i3++) {
            jointRotation = (Vec3s*)objFindJointPoseVector(obj, *p3);
            if (jointRotation != NULL) {
                jointRotation->z = sb;
                jointRotation->x = sa;
            }
            p3++;
        }
    }
    ObjAnim_SampleRootCurvePhase(&obj->anim, baddie->animSpeedA, &baddie->moveSpeed);
    return 0;
}
int dbstealerworm_stateHandlerA07(GameObject* obj, BaddieState* baddie, f32 t) {
    GroundBaddieState* blob = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)blob->control;
    s16 h;
    int q;
    int* ptr;
    int* p2;
    int i2;
    int* p3;
    int i3;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    GameObject* player;
    int flag;
    s16 d;
    int zero;
    Vec3s* jointRotation;
    s16 sa;
    s16 sb;
    f32 frac;
    f32 yawf;

    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    sub->flags15 &= ~4;
    ((void (*)(GameObject*, int))Sfx_KeepAliveLoopedObjectSound)(obj, SFXTRIG_baddie_vambat_death);
    if (baddie->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
    baddie->moveSpeed = 0.01f;
    if (sub->linkedObject == NULL) {
        h = sub->heldScriptSlot;
        if (h != -1) {
            tmpA = sub->messageObjGroup;
            tmpB = sub->messageMode;
            q = (int)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)q, sub->messageCode, tmpB, tmpA);
            q = (int)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)q, 9, 0, h);
            sub->advanceMessage = 1;
            sub->heldScriptSlot = -1;
        }
        if (baddie->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0xf, 0.0f, 0);
            baddie->moveDone = 0;
        }
        frac = blob->aggression / 40.0f;
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer4C, 1.0f, 3.0f) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_weev);
        }
    } else {
        if (RandomTimer_UpdateRangeTrigger(&sub->randomTimer48, 1.0f, 3.0f) != 0) {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie);
        }
        if (baddie->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove(obj, 0x11, 0.0f, 0);
            baddie->moveDone = 0;
        }
        baddie->moveSpeed = 0.018f;
        frac = blob->aggression / 80.0f;
    }
    baddie->stateTag = 0x1f;
    if (dbstealerworm_turnToFaceObjectVertical(obj, baddie->targetObj, 16.0f, frac, 0.2f, t) != 0) {
        sub->advanceMessage = 1;
    }
    if (sub->flags44.flag20 != 0) {
        dbstealerworm_avoidObjects(obj, gDbStealerwormRunToAvoidGroups, gDbStealerwormRunToAvoidWeights, 4, frac);
    } else if (sub->linkedObject == NULL) {
        player = Obj_GetPlayerObject();
        d = Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if ((d >= 0 ? d : -d) < 0x1c71 && yawf < 30.0f) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = objGetLookAtJointKeys();
            zero = 0;
            for (q = 1, ptr = ptr + 1; q < 9; ptr++, q++) {
                jointRotation = (Vec3s*)objFindJointPoseVector(obj, *ptr);
                if (jointRotation != NULL) {
                    jointRotation->z = zero;
                    jointRotation->x = zero;
                }
            }
            player = Obj_GetPlayerObject();
            baddie->targetObj = player;
            tmp2A = sub->messageObjGroup;
            tmp2B = sub->messageMode;
            ptr = (int*)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)ptr, sub->messageCode, tmp2B, tmp2A);
            ptr = (int*)sub->messageStack;
            dbstealerworm_queueMessage((RingBufferQueue*)ptr, 2, 0, 0);
            sub->advanceMessage = 1;
        }
    }
    if (sub->flags44.flag40 != 0) {
        p2 = objGetLookAtJointKeys();
        zero = 0;
        for (i2 = 1, p2 = p2 + 1; i2 < 9; p2++, i2++) {
            jointRotation = (Vec3s*)objFindJointPoseVector(obj, *p2);
            if (jointRotation != NULL) {
                jointRotation->z = zero;
                jointRotation->x = zero;
            }
        }
    } else if (sub->linkedObject == NULL) {
        int dv = -(2535.0f * baddie->animSpeedA);
        int fv = -(2535.0f * baddie->animSpeedB);
        dv = (s16)dv;
        if (dv < -0x500) {
            dv = -0x500;
        } else if (dv > 0x500) {
            dv = 0x500;
        }
        sa = dv;
        fv = (s16)fv;
        if (fv < -0x500) {
            fv = -0x500;
        } else if (fv > 0x500) {
            fv = 0x500;
        }
        sb = fv;
        p3 = objGetLookAtJointKeys();
        i3 = 1;
        p3 = p3 + 1;
        for (; i3 < 9; i3++) {
            jointRotation = (Vec3s*)objFindJointPoseVector(obj, *p3);
            if (jointRotation != NULL) {
                jointRotation->z = sb;
                jointRotation->x = sa;
            }
            p3++;
        }
    }
    ObjAnim_SampleRootCurvePhase(&obj->anim, baddie->animSpeedA, &baddie->moveSpeed);
    return 0;
}

int dbstealerworm_stateHandlerA06(GameObject* obj, BaddieState* baddie) {

    GroundBaddieState* sub = (obj)->extra;
    GroundBaddiePlacement* data = (GroundBaddiePlacement*)(obj)->anim.placementData;
    DbStealerwormControl* control = (DbStealerwormControl*)sub->control;
    BaddieState* bs = baddie;

    bs->stateTag = 0x11;

    if ((s32)bs->moveJustStartedA != 0) {
        f32 fz = 0.0f;
        bs->animSpeedB = fz;
        bs->animSpeedA = fz;
        bs->targetObj = NULL;
        bs->physicsActive = 1;
        bs->hasTarget = 0;
        (obj)->anim.resetHitboxFlags = (u8)((obj)->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
        ObjHits_DisableObject(obj);
        objFreeObjectType(obj, DBSTEALERWORM_OBJGROUP);
        if (control->linkedObject != NULL) {
            ObjMsg_SendToObject((void*)control->linkedObj, 17, obj, 16);
            control->heldScriptSlot = -1;
            control->linkedObj = 0;
        }
    }
    if ((s32)bs->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 1, 0.0f, 0);
        bs->moveDone = 0;
    }
    bs->moveSpeed = 0.008f;
    if ((obj)->anim.currentMoveProgress > 0.8f) {
        int popBuf;
        gameBitIncrement(data->gameBitA);
        if (((u32)data->base.ident + 0x10000) == 0xffff) {
            Obj_FreeObject(obj);
            return 0;
        }
        while (Stack_IsEmpty(control->messageStack) == 0) {
            Stack_Pop(control->messageStack, &popBuf);
        }
        if (data->respawnDelay == 0) {
            (*gMapEventInterface)->addTime(data->base.ident, 360.0f);
        }
        sub->configFlags |= data->flags;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, baddie, 0, 2, gDbStealerwormDeathFootstepSfx);
    (*gPlayerInterface)->playSoundOnEvent0F(obj, baddie, 7, 0, gDbStealerwormBurrowFootstepSfx);
    return 0;
}

int dbstealerworm_stateHandlerA05(GameObject* obj, BaddieState* baddie) {

    BaddieState* bs = baddie;
    DbStealerwormControl* control;
    int frame[3];

    control = (DbStealerwormControl*)(*(GroundBaddieState**)&(obj)->extra)->control;
    if (bs->moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        bs->moveDone = 0;
    }
    if (bs->moveJustStartedA != '\0') {
        int result;
        int staff;
        bs->targetObj = 0;
        if (control->linkedObject != NULL) {
            ObjMsg_SendToObject((void*)control->linkedObj, 17, obj, 16);
            control->linkedObj = 0;
        }
        staff = (int)((GameObject*)Obj_GetPlayerObject())->childObjs[0];
        result = STAFF_INTERFACE(staff)->getHitReactValue((GameObject*)staff);
        if (result != 0) {
            Sfx_PlayFromObject(obj, gDbStealerwormSfxIds[randomGetRange(3, 4)]);
        } else {
            Sfx_PlayFromObject(obj, gDbStealerwormSfxIds[randomGetRange(0, 2)]);
        }
        {
            int frame1;
            int frame2;
            RingBufferQueue* messageStack;
            int frame0;
            frame2 = control->messageObjGroup;
            frame1 = control->messageMode;
            messageStack = control->messageStack;
            frame0 = control->messageCode;
            frame[0] = frame0;
            frame[1] = frame1;
            frame[2] = frame2;
            if (Stack_IsFull(messageStack) == 0) {
                Stack_Push(messageStack, frame);
            }
        }
        control->savedTargetObj = 0;
    }
    bs->stateTag = 16;
    bs->moveSpeed = 0.015f;
    bs->animSpeedA = 0.0f;
    if (bs->moveDone != 0) {
        control->advanceMessage = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA04(GameObject* obj, BaddieState* baddie) {
    GroundBaddieState* state = (obj)->extra;
    BaddieState* bs = baddie;
    u32 eventFlags;
    DbStealerwormControl* sub;
    if (bs->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    bs->moveSpeed = 0.01f;
    if (bs->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove(obj, 0xa, 0.0f, 0);
        bs->moveDone = 0;
    }
    bs->stateTag = 1;
    sub = (DbStealerwormControl*)state->control;
    sub->flags14 = sub->flags14 | DBWORM_FLAG14_FX_DUST;
    eventFlags = bs->eventFlags;
    if (eventFlags & 1) {
        bs->eventFlags = eventFlags & ~BADDIE_EVENT_FOOTSTEP;
        sub->flags14 = sub->flags14 | DBWORM_FLAG14_ATTACK;
    }
    if (bs->moveDone != 0) {
        sub->advanceMessage = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA03(GameObject* obj, BaddieState* baddie) {

    if (baddie->moveJustStartedA != '\0') {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    baddie->moveSpeed = 0.01f;
    if (baddie->moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove(obj, 5, 0.0f, 0);
        baddie->moveDone = 0;
    }
    baddie->stateTag = 1;
    return 0;
}

int dbstealerworm_stateHandlerA02(GameObject* obj, BaddieState* baddie) {

    GroundBaddieState* state = (obj)->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    BaddieState* bs = baddie;

    if (bs->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    if (bs->moveJustStartedA != 0) {
        if (randomGetRange(0, 1) != 0) {
            if (bs->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 6, 0.0f, 0);
                bs->moveDone = 0;
            }
        } else {
            if (bs->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove(obj, 7, 0.0f, 0);
                bs->moveDone = 0;
            }
        }
        bs->stateTag = 1;
        bs->moveSpeed = 0.005f + state->aggression / 20000.0f;
    }
    bs->animSpeedA = 0.0f;
    if (bs->moveDone != 0) {
        sub->advanceMessage = 1;
    }
    sub->flags14 |= DBWORM_FLAG14_FX_DUST;
    return 0;
}

int dbstealerworm_stateHandlerA01(GameObject* obj, BaddieState* baddie) {
    BaddieState* bs = baddie;
    GroundBaddieState* sub;
    DbStealerwormControl* control;
    GroundBaddiePlacement* placementData;

    sub = (obj)->extra;
    placementData = (GroundBaddiePlacement*)(obj)->anim.placementData;
    control = (DbStealerwormControl*)sub->control;
    if (bs->moveJustStartedA != '\0') {
        ObjAnim_SetCurrentMove(obj, 14, 0.0f, 0);
        bs->moveDone = 0;
    }
    (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if ((obj)->anim.currentMoveProgress > 0.25f) {
        control->flags14 |= DBWORM_FLAG14_FX_DUST;
        ObjHits_DisableObject(obj);
    }
    if (bs->moveJustStartedA != '\0') {
        bs->moveSpeed = 0.01f;
        bs->animSpeedA = 0.0f;
    }
    if (bs->moveDone != 0) {
        Sfx_PlayFromObject(obj, SFXTRIG_mn_eggylaugh116);
        control->unk04 = 1.0f;
        ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
        bs->targetObj = 0;
        bs->physicsActive = 0;
        bs->hasTarget = 0;
        sub->targetState = 0;
        sub->configFlags |= placementData->flags;
        if (control->linkedObject != NULL) {
            ObjMsg_SendToObject((void*)control->linkedObj, 17, obj, 19);
            control->linkedObj = 0;
            control->heldScriptSlot = -1;
        }
        if ((control->flags15 & 0x2) == 0) {
            (obj)->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
        }
        control->advanceMessage = 1;
    }
    (*gPlayerInterface)->playSoundOnEvent0F(obj, baddie, 7, 0, gDbStealerwormBurrowFootstepSfx);
    return 0;
}

int dbstealerworm_stateHandlerA00(GameObject* obj, BaddieState* baddie) {

    GroundBaddieState* sub = (obj)->extra;
    DbStealerwormControl* control = (DbStealerwormControl*)sub->control;
    BaddieState* bs = baddie;

    if ((s32)bs->moveJustStartedA != 0) {
        bs->physicsActive = 1;
        (obj)->anim.resetHitboxFlags = (u8)((obj)->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED);
        (obj)->anim.alpha = 255;
        bs->stateTag = 1;
        bs->moveSpeed = 0.012f + (f32)(u32)sub->aggression / 10000.0f;
        ObjHits_EnableObject(obj);
        control->linkedObject = NULL;
        control->heldScriptSlot = -1;
    } else {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DBSTEALERWORM_HIT_VOLUME_SLOT, 1, -1);
    }

    if ((s32)bs->moveDone != 0) {
        sub->targetState = 1;
        control->advanceMessage = 1;
    }

    if ((bs->eventFlags & BADDIE_EVENT_LANDING) != 0) {
        bs->eventFlags = bs->eventFlags & ~BADDIE_EVENT_LANDING;
        control->flags14 = (u8)(control->flags14 | DBWORM_FLAG14_FX_SPRAY);
    }

    if ((obj)->anim.currentMoveProgress < 0.7f) {
        control->flags14 = (u8)(control->flags14 | DBWORM_FLAG14_FX_DUST);
    }

    (*gPlayerInterface)->playSoundOnEvent0F(obj, baddie, 7, 0, gDbStealerwormBurrowFootstepSfx);
    return 0;
}

int dbstealerworm_avoidObjects(GameObject* obj, int* objs, f32* weights, int n, f32 limit) {

    int* objCursor;
    f32* weightCursor;
    BaddieState* state = (obj)->extra;
    int i;
    f32 rangeInit;
    f32 accX;
    f32 accZ;
    GameObject* nearest;
    f32 k;
    f32 scale;
    f32 cosv;
    f32 sinv;
    f32 v;
    f32 w;
    f32 zero;
    struct {
        f32 range;
        f32 d[3];
    } stk;

    accX = 0.0f;
    accZ = 0.0f;
    i = 0;
    objCursor = objs;
    weightCursor = weights;
    rangeInit = 260.0f;
    zero = 0.0f;
    for (; i < n; i++) {
        stk.range = rangeInit;
        nearest = objGetNearestTypeToExcludingSelf(*objCursor, obj, &stk.range);
        if (nearest != 0) {
            if (stk.range == zero) {
                return 0;
            }
            scale = 1.0f;
            k = scale - stk.range / 260.0f;
            k = k * k;
            k = k * k;
            stk.d[0] = nearest->anim.localPosX - (obj)->anim.localPosX;
            stk.d[1] = nearest->anim.localPosY - (obj)->anim.localPosY;
            stk.d[2] = nearest->anim.localPosZ - (obj)->anim.localPosZ;
            stk.d[0] = stk.d[0] * (scale / stk.range);
            stk.d[1] = stk.d[1] * (scale / stk.range);
            stk.d[2] = stk.d[2] * (scale / stk.range);
            accX = accX - limit * (stk.d[0] * k * (w = *weightCursor));
            accZ = accZ - limit * (stk.d[2] * k * (v = w));
        }
        objCursor++;
        weightCursor++;
    }
    cosv = mathSinf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
    sinv = mathCosf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
    state->animSpeedB = state->animSpeedB + (accX * sinv - accZ * cosv);
    state->animSpeedA = state->animSpeedA + (-accZ * sinv - accX * cosv);
    v = state->animSpeedA;
    if (v < -limit) {
        v = -limit;
    } else if (v > limit) {
        v = limit;
    }
    state->animSpeedA = v;
    v = state->animSpeedB;
    state->animSpeedB = (v < -limit) ? -limit : (v > limit) ? limit : v;
    return 0;
}

int dbstealerworm_turnToFaceObject(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused,
                                   f32 range) {
    BaddieState* state = (obj)->extra;
    f32 yawF;
    s16 yaw;
    f32 zero;
    f32 a;
    f32 ratio;

    yaw = Obj_GetYawDeltaToObject(obj, otherObj, &yawF);
    zero = 0.0f;
    if (zero == range) {
        return 0;
    }
    yawF -= yawOffset;
    ratio = yawF / range;
    yawF = ratio;
    if (ratio >= zero) {
        a = ratio;
    } else {
        a = -ratio;
    }
    if (a < 10.0f) {
        return 1;
    }
    if (ratio < 0.0f) {
        speed = -speed;
    }
    dbstealerworm_updateTurnSpeed(state, yaw, speed);
    return 0;
}

int dbstealerworm_turnToFaceObjectVertical(GameObject* obj, GameObject* otherObj, f32 yawOffset, f32 speed, f32 unused,
                                           f32 range) {
    BaddieState* state = obj->extra;
    f32 yawF;
    s16 yaw;
    f32 dy;
    f32 zero;

    if (obj == NULL || otherObj == NULL) {
        return 0;
    }
    yaw = Obj_GetYawDeltaToObject(obj, otherObj, &yawF);
    zero = 0.0f;
    if (zero == range) {
        return 0;
    }
    if (yawF < yawOffset) {
        dy = (obj->anim.localPosY - otherObj->anim.localPosY >= zero)
                 ? obj->anim.localPosY - otherObj->anim.localPosY
                 : -(obj->anim.localPosY - otherObj->anim.localPosY);
        if (dy < 8.0f) {
            return 1;
        }
    }
    dbstealerworm_updateTurnSpeed(state, yaw, speed);
    return 0;
}

void dbstealerworm_launchIceBall(GameObject* obj, BaddieState* baddie) {

    ObjPlacement* setup;
    GameObject* newObj;
    f32 dur;
    f32 t;
    u8 canSetupObject;

    canSetupObject = Obj_CanSetupObject();
    if (canSetupObject > 0) {
        setup = Obj_AllocObjectSetup(0x24, DBSTEALERWORM_CHILD_OBJ_ICE_BALL_SMALL);
        setup->posX = (obj)->anim.localPosX;
        setup->posY = 15.0f + (obj)->anim.localPosY;
        setup->posZ = (obj)->anim.localPosZ;
        setup->color[0] = 1;
        setup->color[1] = 1;
        setup->color[2] = 0xff;
        setup->color[3] = 0xff;
        newObj = objSetupObject(setup, 5, (obj)->anim.mapEventSlot, -1, NULL);
        if (newObj != NULL) {
            t = baddie->targetDistance / 200.0f;
            dur = 50.0f * t;
            newObj->anim.velocityX = (((GameObject*)baddie->targetObj)->anim.localPosX - (obj)->anim.localPosX) / dur;
            newObj->anim.velocityY =
                ((90.0f * t + ((GameObject*)baddie->targetObj)->anim.localPosY) - (obj)->anim.localPosY) / dur;
            newObj->anim.velocityZ = (((GameObject*)baddie->targetObj)->anim.localPosZ - (obj)->anim.localPosZ) / dur;
            newObj->ownerObj = obj;
        }
    }
}
void dbstealerworm_processEffectFlags(GameObject* obj, GroundBaddieState* baddie) {
    int i;
    DbStealerwormControl* state = (DbStealerwormControl*)baddie->control;
    if ((state->flags14 & DBWORM_FLAG14_ATTACK) && baddie->baddie.targetObj != 0) {
        ((void (*)(GameObject*, int))dbstealerworm_launchIceBall)(obj, (int)baddie);
    }
    if (state->flags14 & DBWORM_FLAG14_FX_DUST) {
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_DUST, NULL, 2, -1, NULL);
    }
    if (state->flags14 & DBWORM_FLAG14_FX_SPRAY) {
        for (i = 0; i < 0xa; i++) {
            (*gPartfxInterface)->spawnObject((void*)obj, DBSTEALERWORM_PARTFX_SPRAY, NULL, 1, -1, NULL);
        }
    }
    state->flags14 = 0;
}

void dbstealerworm_acquireTarget(GameObject* obj, GroundBaddieState* groundState, int baddie) {

    GroundBaddieState* st = groundState;
    DbStealerwormControl* sub = (DbStealerwormControl*)st->control;
    GameObject* near;
    GroundBaddiePlacement* data;
    GameObject* player;
    f32 dist;
    struct {
        f32 range;
        f32 d[3];
    } stk;
    stk.range = 100.0f;
    data = (GroundBaddiePlacement*)obj->anim.placementData;
    near = (*gBaddieControlInterface)->findAggroTarget(obj, (void*)baddie, st->aggroRange, 0x8000);
    if (near == 0 && (st->configFlags & 0x10) != 0) {
        near = objGetNearestTypeTo(DBEGG_OBJGROUP, obj, &stk.range);
    }
    if (near == 0 && (st->configFlags & 0x10) != 0 && (st->configFlags & 2) == 0 && (data->flags & 2) != 0) {
        near = objGetNearestTypeTo(DBEGG_OBJGROUP, obj, 0);
    }
    if (near != 0 && (st->configFlags & 2) == 0) {
        (*gBaddieControlInterface)
            ->startHitReaction(obj, (void*)baddie, &groundState->routeNav, st->gameBitB, NULL, 0, 0, 8, -1);
        ((BaddieState*)baddie)->targetObj = near;
        ((BaddieState*)baddie)->hasTarget = 0;
        objAddObjectType(obj, DBSTEALERWORM_OBJGROUP);
        st->targetState = 1;
    } else {
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            stk.d[0] = player->anim.worldPosX - obj->anim.worldPosX;
            stk.d[1] = player->anim.worldPosY - obj->anim.worldPosY;
            stk.d[2] = player->anim.worldPosZ - obj->anim.worldPosZ;
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        } else {
            dist = 10000.0f;
        }
        if (sub->countdown > sub->nextSfxTime && dist < 400.0f) {
            Sfx_PlayFromObject(obj, gDbStealerwormBurrowFootstepSfx[1]);
            sub->nextSfxTime = sub->nextSfxTime + (f32)randomGetRange(0x32, 0xfa);
        }
        sub->countdown += timeDelta;
    }
}

int dbstealerworm_handleMessage(GameObject* obj, u8 msg, int* out) {
    GroundBaddieState* state = obj->extra;
    DbStealerwormControl* sub = (DbStealerwormControl*)state->control;
    int result = 0;
    u8 configFlags;
    switch (msg) {
    case 0x80:
        break;
    case 0x81:
        configFlags = state->configFlags;
        if ((configFlags & 2) == 0) {
            break;
        }
        state->configFlags = configFlags & ~2;
        if (out != 0) {
            *out = 1;
        }
        result = 1;
        break;
    case 0x82:
        if (state->baddie.controlMode != 0xb) {
            break;
        }
        if (out == 0) {
            break;
        }
        sub->savedTargetObj = (int)out;
        result = 1;
        break;
    case 0x83:
        result = sub->savedTargetObj;
        break;
    }
    return result;
}

s16 dbstealerworm_getControlMode(GameObject* obj) {
    return ((BaddieState*)obj->extra)->controlMode;
}

int dbstealerworm_getExtraSize(void) {
    return sizeof(GroundBaddieState) + sizeof(DbStealerwormControl);
}
int dbstealerworm_getObjectTypeId(void) {
    return 0x49;
}

void dbstealerworm_free(GameObject* obj) {
    GroundBaddieState* sub = obj->extra;
    DbStealerwormControl* p40c = sub->control;
    objFreeObjectType(obj, DBSTEALERWORM_OBJGROUP);
    Stack_Free(p40c->messageStack);
    if (obj->childObjs[0] != NULL) {
        Obj_FreeObject(obj->childObjs[0]);
        obj->childObjs[0] = NULL;
    }
    (*gBaddieControlInterface)->releaseState(obj, sub, 3);
}

void dbstealerworm_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible) {
    GroundBaddieState* state;
    GameObject* path;
    DbStealerwormControl* sub;

    state = (obj)->extra;
    sub = (DbStealerwormControl*)state->control;
    if (sub->linkedObject != NULL) {
        ((GameObject*)sub->linkedObj)->anim.localPosX = (obj)->anim.localPosX;
        ((GameObject*)sub->linkedObj)->anim.localPosY = (obj)->anim.localPosY;
        ((GameObject*)sub->linkedObj)->anim.localPosZ = (obj)->anim.localPosZ;
        ((GameObject*)sub->linkedObj)->anim.localPosY += 30.0f;
    }
    if (visible == 0 || (obj)->userData1 != 0 || state->targetState == 0) {
        return;
    }
    {
        {
            f32 zero = 0.0f;
            if (state->glowAlpha != zero) {
                objSetGlowColor(0xc8, 0, 0, state->glowAlpha);
            }
            objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
            if ((state->flags400 & 0x60) != 0) {
                objDoParticleFx(obj, 1.0f, 3, state->glowAlpha, 0);
            }
            path = sub->linkedObject;
            if (path != NULL && path->anim.modelInstance != NULL) {
                ObjPath_GetPointWorldPosition(obj, 3, &path->anim.localPosX, &path->anim.localPosY,
                                              &path->anim.localPosZ, 0);
                objRenderModelAndHitVolumes(sub->linkedObject, p2, p3, p4, p5, 1.0f);
            }
        }
    }
}

void dbstealerworm_hitDetect(GameObject* obj) {
    int* inner = obj->extra;
    (*gPlayerInterface)->updateVelocityState(obj, inner, gDBStealerWormStateHandlersA);
}

const f32 gDbStealerwormGravity[1] = {0.17f};

void dbstealerworm_update(GameObject* obj) {
    DbWormEffectSpawnWork* st[1];
    char* tbl;
    GroundBaddieState* blob;
    GroundBaddiePlacement* data;
    DbStealerwormControl* sub;
    DbWormMsgGroup* grp;
    DbStealerwormControl* sub3;
    int n;
    DbStealerwormControl* sub2;
    GameObject* t;
    struct {
        u32 msg;
        int argA;
        int argB;
        f32 v[3];
    } stk;

    st[0] = &gDbWormEffectSpawnWork;
    tbl = (char*)gDbStealerwormScriptStealEggThrowToWorm;
    blob = obj->extra;
    data = (GroundBaddiePlacement*)obj->anim.placementData;
    sub = blob->control;
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
    if (sub->flags44.flag10) {
        grp = &((DbWormMsgGroup*)(tbl + 0x15c))[data->unk24];
        sub->messageStack = Queue_Alloc(0x14, 0xc);
        n = grp->count;
        for (; n != 0;) {
            Stack_Push(sub->messageStack, (int*)((int)grp->msgs + --n * 12));
        }
        sub->advanceMessage = 1;
        sub->flags44.flag10 = 0;
    }
    if (mainGetBit(blob->gameBitC) != 0) {
        if (obj->userData1 != 0) {
            if ((blob->configFlags & 4) == 0 && (*gMapEventInterface)->shouldNotSaveTime(data->base.ident) != 0) {
                (*gBaddieControlInterface)->initGroundBaddie(obj, (u8*)data, (u8*)blob, 0x10, 7, 0x10a, 0x26, 20.0f);
                objAddObjectType(obj, DBSTEALERWORM_OBJGROUP);
                blob->targetState = 0;
                ObjAnim_SetCurrentMove(obj, 8, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
                blob->baddie.moveDone = 0;
                obj->anim.alpha = 0xff;
                obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;
            }
        } else if (obj->userData2 == 0) {
            obj->anim.localPosX = data->base.posX;
            obj->anim.localPosY = data->base.posY;
            obj->anim.localPosZ = data->base.posZ;
            (*gObjectTriggerInterface)->runSequence(data->sequenceId, (void*)obj, -1);
            obj->userData2 = 1;
        } else {
            if ((*gBaddieControlInterface)->isObjectValid(obj, blob, 0) == 0) {
                blob->targetState = 0;
            } else {
                t = blob->baddie.targetObj;
                if (blob->baddie.targetObj != NULL) {
                    stk.v[0] = t->anim.worldPosX - obj->anim.worldPosX;
                    stk.v[1] = t->anim.worldPosY - obj->anim.worldPosY;
                    stk.v[2] = t->anim.worldPosZ - obj->anim.worldPosZ;
                    blob->baddie.targetDistance =
                        sqrtf(stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = ((GroundBaddieState*)obj->extra)->control;
                while (ObjMsg_Pop(obj, &stk.msg, (u32*)&stk.argB, &stk.msg + 1) != 0) {
                    if (stk.msg == 0x11 && sub2->heldScriptSlot != -1) {
                        ObjMsg_SendToObject((void*)sub2->linkedObj, 0x11, (void*)obj, 0x14);
                        sub2->linkedObj = 0;
                        sub2->heldScriptSlot = -1;
                        ObjAnim_SetCurrentMove(obj, 0xf, 0.0f, 0);
                    }
                }
                if ((*gBaddieControlInterface)
                        ->updateHitReaction(obj, (void*)blob, &blob->routeNav, blob->gameBitB, (int*)(tbl + 0x2ac),
                                            (u8*)(tbl + 0x324), 1, st[0]) != 0) {
                    st[0]->posX = obj->anim.localPosX;
                    st[0]->posY = obj->anim.localPosY;
                    st[0]->posZ = obj->anim.localPosZ;
                    objDoHitParticleFx((void*)obj, 0.014f, st[0], 1, 0);
                }
                if (blob->targetState == 0) {
                    dbstealerworm_acquireTarget(obj, blob, (int)blob);
                } else {
                    sub3 = blob->control;
                    ((void (*)(GameObject*, int))dbstealerworm_processEffectFlags)(obj, (int)blob);
                    (*gBaddieControlInterface)->updateGravity(obj, (void*)blob, gDbStealerwormGravity[0], -1);
                    if ((sub3->flags15 & 4) == 0) {
                        (*gPlayerInterface)->rotateTowardTarget((void*)obj, (void*)blob, timeDelta, 4);
                    }
                    blob->savedPendingParentObj = obj->pendingParentObj;
                    obj->pendingParentObj = 0;
                    /* Retail derives both pointers past the 0x18-byte scratch record. */
                    (*gPlayerInterface)
                        ->update((void*)obj, (void*)blob, timeDelta, timeDelta, (char*)st[0] + 0x34,
                                 (char*)st[0] + 0x18);
                    obj->pendingParentObj = blob->savedPendingParentObj;
                }
            }
        }
    }
}

void dbstealerworm_init(GameObject* obj, u8* def, int flag) {
    GroundBaddieState* sub;
    DbStealerwormControl* p40c;
    u8 mode;
    int randomValue;

    sub = obj->extra;
    mode = 6;
    if (flag != 0) {
        mode |= 1;
    }
    (*gBaddieControlInterface)->initGroundBaddie(obj, def, (u8*)sub, 0x10, 7, 0x10a, mode, 20.0f);
    objAddObjectType(obj, DBSTEALERWORM_OBJGROUP);
    obj->animEventCallback = NULL;
    p40c = sub->control;
    memset(p40c, 0, sizeof(DbStealerwormControl));
    p40c->unk08 = 20.0f;
    p40c->script = &gDbStealerwormScriptTable[((GroundBaddiePlacement*)def)->unk24];
    randomValue = randomGetRange(0xa, 0x12c);
    p40c->countdown = (f32)(s32)randomValue;
    p40c->flags44.flag20 = ((GroundBaddiePlacement*)def)->flags & 1;
    p40c->flags44.flag10 = 1;
    p40c->linkedObj = 0;
    ObjAnim_SetCurrentMove(obj, 8, 0.0f, 0);
    obj->anim.resetHitboxFlags = (u8)(obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED);
    (*gPlayerInterface)->setState(obj, sub, 3);
    sub->baddie.substate = 0;
    sub->baddie.physicsActive = 1;
    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    if (obj->anim.modelState != NULL) {
        obj->anim.modelState->flags |= 0x4008;
    }
}

void dbstealerworm_release(void) {
}

void dbstealerworm_initialise(void) {
    DBstealerwo_setFuncPtrs();
}

void DBstealerwo_setFuncPtrs(void) {
    gDBStealerWormStateHandlersA[0] = dbstealerworm_stateHandlerA00;
    gDBStealerWormStateHandlersA[1] = dbstealerworm_stateHandlerA01;
    gDBStealerWormStateHandlersA[2] = dbstealerworm_stateHandlerA02;
    gDBStealerWormStateHandlersA[3] = dbstealerworm_stateHandlerA03;
    gDBStealerWormStateHandlersA[4] = dbstealerworm_stateHandlerA04;
    gDBStealerWormStateHandlersA[5] = dbstealerworm_stateHandlerA05;
    gDBStealerWormStateHandlersA[6] = dbstealerworm_stateHandlerA06;
    gDBStealerWormStateHandlersA[7] = dbstealerworm_stateHandlerA07;
    gDBStealerWormStateHandlersA[8] = dbstealerworm_stateHandlerA08;
    gDBStealerWormStateHandlersA[9] = dbstealerworm_stateHandlerA09;
    gDBStealerWormStateHandlersA[10] = dbstealerworm_stateHandlerA0A;
    gDBStealerWormStateHandlersA[11] = dbstealerworm_stateHandlerA0B;
    gDBStealerWormStateHandlersA[12] = dbstealerworm_stateHandlerA0C;
    gDBStealerWormStateHandlersA[13] = dbstealerworm_stateHandlerA0D;
    gDBStealerWormStateHandlersA[14] = dbstealerworm_stateHandlerA0E;
    gDBStealerWormStateHandlersA[15] = dbstealerworm_stateHandlerA0F;
    gDBStealerWormStateHandlersB[0] = dbstealerworm_stateHandlerB00;
    gDBStealerWormStateHandlersB[1] = dbstealerworm_stateHandlerB01;
    gDBStealerWormStateHandlersB[2] = dbstealerworm_stateHandlerB02;
    gDBStealerWormStateHandlersB[3] = dbstealerworm_stateHandlerB03;
    gDBStealerWormStateHandlersB[4] = dbstealerworm_stateHandlerB04;
    gDBStealerWormStateHandlersB[5] = dbstealerworm_stateHandlerB05;
    gDBStealerWormStateHandlersB[6] = dbstealerworm_stateHandlerB06;
}

typedef enum DbStealerwormCmd {
    DBSTEALERWORM_CMD_POP_OUT_OF_GROUND,
    DBSTEALERWORM_CMD_BURST_INTO_GROUND,
    DBSTEALERWORM_CMD_BITE_ATTACK,
    DBSTEALERWORM_CMD_STAND_STILL,
    DBSTEALERWORM_CMD_STAND_AND_SPIT,
    DBSTEALERWORM_CMD_HIT_FIGHT_MAIN,
    DBSTEALERWORM_CMD_FIGHT_DIE,
    DBSTEALERWORM_CMD_RUNTO_OBJECT,
    DBSTEALERWORM_CMD_RUNTO_THROW_OBJ,
    DBSTEALERWORM_CMD_PICKUP_OBJECT,
    DBSTEALERWORM_CMD_THROW_AT_OBJECT,
    DBSTEALERWORM_CMD_WAIT_FOR_OBJECT,
    DBSTEALERWORM_CMD_WAIT_FOR_THROW,
    DBSTEALERWORM_CMD_TRY_TO_CATCH,
    DBSTEALERWORM_CMD_CATCH_OBJECT,
    DBSTEALERWORM_CMD_KILL_OBJECT
} DbStealerwormCmd;

#define DBSTEALERWORM_CMD_COUNT 16

DbStealerwormScriptStep gDbStealerwormScriptStealEggThrowToWorm[6] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},
    {DBSTEALERWORM_CMD_RUNTO_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_PICKUP_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_RUNTO_THROW_OBJ, 0, DBSTEALERWORM_OBJGROUP},
    {DBSTEALERWORM_CMD_THROW_AT_OBJECT, 0, DBSTEALERWORM_OBJGROUP},
    {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScriptStep gDbStealerwormScriptStealEggThrowToGroup30[6] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},          {DBSTEALERWORM_CMD_RUNTO_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_PICKUP_OBJECT, 0, DBEGG_OBJGROUP}, {DBSTEALERWORM_CMD_RUNTO_THROW_OBJ, 0, 30},
    {DBSTEALERWORM_CMD_THROW_AT_OBJECT, 0, 30},           {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScriptStep gDbStealerwormScriptStealEggCarryToGroup30[5] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},          {DBSTEALERWORM_CMD_RUNTO_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_PICKUP_OBJECT, 0, DBEGG_OBJGROUP}, {DBSTEALERWORM_CMD_RUNTO_OBJECT, 0, 30},
    {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScriptStep gDbStealerwormScriptStealEggThrowToGroup0[6] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},
    {DBSTEALERWORM_CMD_RUNTO_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_PICKUP_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_RUNTO_THROW_OBJ, 0, 0},
    {DBSTEALERWORM_CMD_THROW_AT_OBJECT, 0, 0},
    {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScriptStep gDbStealerwormScriptWaitForEgg[3] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},
    {DBSTEALERWORM_CMD_WAIT_FOR_OBJECT, 0, DBEGG_OBJGROUP},
    {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScriptStep gDbStealerwormScriptKillTarget[3] = {
    {DBSTEALERWORM_CMD_POP_OUT_OF_GROUND, 0, 0},
    {DBSTEALERWORM_CMD_KILL_OBJECT, 0, 0},
    {DBSTEALERWORM_CMD_BURST_INTO_GROUND, 0, 0},
};
DbStealerwormScript gDbStealerwormScriptTable[6] = {
    {gDbStealerwormScriptStealEggThrowToWorm, 6, 0},
    {gDbStealerwormScriptStealEggThrowToGroup30, 6, 0},
    {gDbStealerwormScriptStealEggCarryToGroup30, 5, 0},
    {gDbStealerwormScriptStealEggThrowToGroup0, 6, 0},
    {gDbStealerwormScriptWaitForEgg, 3, 0},
    {gDbStealerwormScriptKillTarget, 3, 0},
};
char gDbStealerwormCommandNames[DBSTEALERWORM_CMD_COUNT][15] = {
    "popOutOfGround", "burstIntoGroun", "biteAttack    ", "standStill    ", "standAndSpit  ", "hitFightMain  ",
    "fight_die     ", "runto_Object  ", "runto_ThrowObj", "pickup_Object ", "throw_AtObject", "wait_forObject",
    "Wait_for_throw", "try_to_catch  ", "catch_Object  ", "Kill_Object   "};
int gDbStealerwormDeathFootstepSfx[3] = {0x000001ed, 0x000001ed, 0x000001ec};
int gDbStealerwormBurrowFootstepSfx[4] = {0x00000000, 0x000001f0, 0x000001f1, 0x000001f1};

int gDbStealerwormSfxIds[] = {
    498, 498, 498, 149, 149, 5, 5, 5, 5, 5, 5, 5, 5, 5,  5,  5,  5,  5,  5,  2,  5,      5,
    5,   5,   5,   5,   5,   5, 5, 5, 5, 5, 5, 5, 5, -1, -1, -1, -1, -1, -1, -1, -65536,
};

int gDbStealerwormRunToAvoidGroups[4] = {0, 1, 3, 10};
f32 gDbStealerwormRunToAvoidWeights[4] = {2.0f, 4.0f, 1.5f, 3.0f};
int gDbStealerwormWaitAvoidGroups[4] = {3, 0, 1, 10};
f32 gDbStealerwormWaitAvoidWeights[4] = {8.0f, 3.0f, 2.0f, 4.0f};
int gDbStealerwormKillAvoidGroups[4] = {3, 1, 0, 10};
f32 gDbStealerwormKillAvoidWeights[10] = {2.0f, 0.8f, 0.4f, 2.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
typedef struct DbStealerwormObjDescriptorLayout {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    void (*callbacks[12])(void);
    char debugStrings[0x5C];
} DbStealerwormObjDescriptorLayout;

void* gDBStealerWormStateHandlersA[17];

DbStealerwormObjDescriptorLayout gDBstealerwormObjDescriptor = {
    0,
    0,
    0,
    0x000b0000,
    {
        (void (*)(void))dbstealerworm_initialise,
        (void (*)(void))dbstealerworm_release,
        0,
        (void (*)(void))dbstealerworm_init,
        (void (*)(void))dbstealerworm_update,
        (void (*)(void))dbstealerworm_hitDetect,
        (void (*)(void))dbstealerworm_render,
        (void (*)(void))dbstealerworm_free,
        (void (*)(void))dbstealerworm_getObjectTypeId,
        (void (*)(void))dbstealerworm_getExtraSize,
        (void (*)(void))dbstealerworm_getControlMode,
        (void (*)(void))dbstealerworm_handleMessage,
    },
    " Stack -------------------\n\000%i : %s : Opand %i \n\000\000\000\000 HAS BALL : %x= %x\n\000 THROW "
    "CHANCE %i \n",
};
