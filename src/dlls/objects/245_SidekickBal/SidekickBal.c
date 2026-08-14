/*
 * SidekickBal (DLL 0xF5) - Tricky's fetch ball.
 *
 * The ball moves between idle, held, thrown, rolling, and fading states.
 * Path-control collision data drives its floor response and surface
 * reflection, while Tricky and the player coordinate throws via messages.
 */
#include "dlls/objects/245_SidekickBal.h"
#include "dolphin/mtx/vec.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/pad.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/debug.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/player_state.h"
#include "main/frame_timing.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/obj_message.h"
#include "main/obj_trigger.h"
#include "main/object_render.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/vecmath.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/tricky_api.h"
#include "main/dll/player_api.h"
#include "main/audio/sfx_play_api.h"

extern char sSidekickBallYVelDepthFormat[];
extern char sSidekickBallDotFormat[];
extern f32 gSidekickBallPathPointData[];

#define SIDEKICKBALL_MESSAGE_PLAYER_GRAB 0x100010

#define SIDEKICKBALL_Y_ITEM_ID 5

#define SIDEKICKBALL_RENDER_SCALE 1.0f

#define SIDEKICKBALL_THROW_SCALE         0.75f
#define SIDEKICKBALL_THROW_INPUT_SCALE   0.25f
#define SIDEKICKBALL_THROW_BASE_SPEED    2.2f
#define SIDEKICKBALL_FADE_DURATION       60.0f
#define SIDEKICKBALL_ACTIVE_TIMEOUT      300.0f
#define SIDEKICKBALL_MAX_ALPHA           255.0f
#define SIDEKICKBALL_RESTITUTION         0.7f
#define SIDEKICKBALL_MOVEMENT_EPSILON    0.01f
#define SIDEKICKBALL_FLOOR_DAMPING       0.95f
#define SIDEKICKBALL_FLOOR_ACCELERATION  0.025f
#define SIDEKICKBALL_FLOOR_SETTLE_SPEED  0.2f
#define SIDEKICKBALL_FLOOR_SETTLE_DEPTH  1.0f
#define SIDEKICKBALL_GRAVITY             0.05f
#define SIDEKICKBALL_BOUNCE_SOUND_SPEED  0.5f
#define SIDEKICKBALL_STOP_BOUNCING_SPEED 0.3f

#define SIDEKICKBALL_PATH_FLAG        5
#define SIDEKICKBALL_PATH_CONFIG      0x40007
#define SIDEKICKBALL_MESSAGE_CAPACITY 1

static inline int sidekickBall_floatsEqual(f32 a, f32 b) {
    return a == b;
}

static inline int sidekickBall_floatsNotEqual(f32 a, f32 b) {
    return a != b;
}

int sidekickBall_isIdle(GameObject* obj) {
    SidekickBallState* state = obj->extra;
    return state->ballMode == SIDEKICK_BALL_IDLE;
}

static inline void sidekickBall_throw(GameObject* obj, f32 velocityX, f32 velocityY, f32 velocityZ) {
    SidekickBallState* state = obj->extra;
    int objectId;
    state->ballMode = SIDEKICK_BALL_THROWN;
    state->fadeTimer = 0.0f;
    obj->anim.velocityX = velocityX;
    obj->anim.velocityY = velocityY;
    obj->anim.velocityZ = velocityZ;
    ObjHits_EnableObject((GameObject*)(objectId = (int)obj));
    ObjHits_SyncObjectPositionIfDirty((GameObject*)objectId);
    state->hittableLatch = 1;
    state->previousPosX = obj->anim.localPosX;
    state->previousPosY = obj->anim.localPosY;
    state->previousPosZ = obj->anim.localPosZ;
}

void sidekickBall_handlePlayerInteraction(GameObject* obj, SidekickBallState* state) {
    GameObject* player;
    PlayerState* playerState;
    s16 selectedItem;
    u32 buttons;
    MatrixTransform rotationArg;

    player = Obj_GetPlayerObject();
    playerState = player->extra;

    if (state->triggerArmed == 1)
        return;

    if (state->triggerHit == 0) {
        state->triggerHit = 1;
        if (state->triggerHit == 0)
            return;
        state->sendHoldMessage = 1;
        return;
    }

    ObjHits_DisableObject(obj);
    obj->anim.resetHitboxFlags |= INTERACT_FLAG_DISABLED;

    getYButtonItem(&selectedItem);
    buttons = getButtonsJustPressed(0);
    if ((buttons & PAD_BUTTON_A) != 0 ||
        (selectedItem == SIDEKICKBALL_Y_ITEM_ID && (getButtonsJustPressed(0) & PAD_BUTTON_Y) != 0)) {
        if (isTrickyNear(player) != 0) {
            state->sendHoldMessage = 0;
        } else {
            Sfx_PlayFromObject(0, SFXTRIG_id_10a);
        }
    }

    if (obj->userData2 == 1) {
        state->triggerHit = 2;
    }
    if (state->triggerHit == 2 && obj->userData2 == 0) {
        if (playerIsThrowing(player) != 0) {
            state->triggerHit = 0;
            state->triggerArmed = 1;

            {
                f32 throwScale = SIDEKICKBALL_THROW_SCALE;
                obj->anim.velocityY =
                    throwScale * (SIDEKICKBALL_THROW_INPUT_SCALE * playerState->baddie.inputMagnitude +
                                  SIDEKICKBALL_THROW_BASE_SPEED);
                obj->anim.velocityZ =
                    throwScale * (-SIDEKICKBALL_THROW_INPUT_SCALE * playerState->baddie.inputMagnitude +
                                  -SIDEKICKBALL_THROW_BASE_SPEED);
            }

            rotationArg.x = 0.0f;
            rotationArg.y = 0.0f;
            rotationArg.z = 0.0f;
            rotationArg.scale = 1.0f;
            rotationArg.rotZ = 0;
            rotationArg.rotY = 0;
            {
                s16 rotationX;
                if (player->anim.parent != NULL) {
                    rotationX = ((ObjAnimComponent*)player->anim.parent)->rotX + player->anim.rotX;
                } else {
                    rotationX = player->anim.rotX;
                }
                rotationArg.rotX = rotationX;
            }
            vecRotateZXY(&rotationArg.rotX, &obj->anim.velocityX);

            sidekickBall_throw(obj, obj->anim.velocityX, obj->anim.velocityY, obj->anim.velocityZ);
        } else {
            state->triggerHit = 0;
            state->sendHoldMessage = 0;
            state->fadeTimer = SIDEKICKBALL_FADE_DURATION;
            state->ballMode = SIDEKICK_BALL_FADING;
        }
    }
    if (state->sendHoldMessage != 0) {
        ObjMsg_SendToObject(player, SIDEKICKBALL_MESSAGE_PLAYER_GRAB, (void*)obj, 0);
    }
}

void sidekickBall_keepAlive(GameObject* obj) {
    SidekickBallState* state = obj->extra;
    u8 mode = state->ballMode;
    if (mode != SIDEKICK_BALL_THROWN && mode != SIDEKICK_BALL_HELD)
        return;
    state->fadeTimer = 0.0f;
}

int sidekickBall_isHeldOrMoving(GameObject* obj) {
    int result = 0;
    u8 mode = (*(SidekickBallState**)&obj->extra)->ballMode;
    if (mode == SIDEKICK_BALL_HELD || mode == SIDEKICK_BALL_MOVING)
        result = 1;
    return result;
}

void sidekickBall_setIdle(GameObject* obj, GameObject* source) {
    SidekickBallState* state = obj->extra;
    state->fadeTimer = 0.0f;
    state->ballMode = SIDEKICK_BALL_IDLE;
    ObjHits_DisableObject(obj);
    state->hittableLatch = 0;
}

void sidekickBall_launch(GameObject* obj, GameObject* source, f32 velocityX, f32 velocityY, f32 velocityZ) {
    SidekickBallState* state = obj->extra;
    int objectId;
    state->ballMode = SIDEKICK_BALL_THROWN;
    state->fadeTimer = 0.0f;
    obj->anim.velocityX = velocityX;
    obj->anim.velocityY = velocityY;
    obj->anim.velocityZ = velocityZ;
    ObjHits_EnableObject((GameObject*)(objectId = (int)obj));
    ObjHits_SyncObjectPositionIfDirty((GameObject*)objectId);
    state->hittableLatch = 1;
    state->previousPosX = obj->anim.localPosX;
    state->previousPosY = obj->anim.localPosY;
    state->previousPosZ = obj->anim.localPosZ;
}

int SidekickBall_getExtraSize(void) {
    return sizeof(SidekickBallState);
}

void SidekickBall_free(int obj) {
    mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 1);
}

void SidekickBall_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible) {
    if (obj->userData2 == 0 || visible == -1) {
        objRenderModelAndHitVolumes(obj, fwdArg2, fwdArg3, fwdArg4, fwdArg5, SIDEKICKBALL_RENDER_SCALE);
    }
}

void SidekickBall_update(GameObject* obj) {
    SidekickBallState* state;
    GameObject* player;
    GameObject* tricky;
    u32 trickyFlagsZeroCount;
    int trickyFlagsMask;
    int triggered;

    state = (SidekickBallState*)(int)obj->extra;
    obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
    state->onPathPoint = 0;

    player = Obj_GetPlayerObject();
    tricky = getTrickyObject();
    if (player == NULL || (player->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 || tricky == NULL ||
        (trickyFlagsZeroCount = __cntlzw((u32)tricky->objectFlags), trickyFlagsMask = trickyFlagsZeroCount >> 5,
         (trickyFlagsMask & OBJECT_OBJFLAG_PARENT_SLACK) != 0) ||
        mainGetBit(GAMEBIT_NoBallsAllowed) != 0) {
        Obj_FreeObject(obj);
        return;
    }

    if (state->ballMode == SIDEKICK_BALL_THROWN || state->ballMode == SIDEKICK_BALL_HELD ||
        state->ballMode == SIDEKICK_BALL_MOVING) {
        state->fadeTimer = state->fadeTimer + timeDelta;
        if (state->fadeTimer >= SIDEKICKBALL_ACTIVE_TIMEOUT) {
            state->fadeTimer = 0.0f;
            state->ballMode = SIDEKICK_BALL_FADING;
        }
    }

    switch (state->ballMode) {
    case SIDEKICK_BALL_THROWN:
        state->ballMode = trickyBallMove(obj);
        return;
    case SIDEKICK_BALL_MOVING:
        trickyBallMove(obj);
        /* Fall through to process player interaction triggers. */
    case SIDEKICK_BALL_HELD:
        obj->anim.resetHitboxFlags = obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
        triggered = 0;
        if ((buttonGetDisabled(0) & PAD_BUTTON_A) == 0u && obj->userData2 == 0 && ObjTrigger_IsSet(obj) != 0) {
            ObjHits_DisableObject(obj);
            triggered = 1;
        }
        state->triggerHit = triggered;
        if (state->triggerHit != 0) {
            state->triggerArmed = 0;
            state->triggerHit = 0;
            state->ballMode = SIDEKICK_BALL_IDLE;
        }
        break;
    case SIDEKICK_BALL_FADING:
        state->fadeTimer = state->fadeTimer + timeDelta;
        if (state->fadeTimer >= SIDEKICKBALL_FADE_DURATION) {
            Obj_FreeObject(obj);
            return;
        }
        {
            f32 fadeAlpha = SIDEKICKBALL_MAX_ALPHA * state->fadeTimer / SIDEKICKBALL_FADE_DURATION;
            obj->anim.alpha = (u8)(0xFF - (int)fadeAlpha);
        }
        break;
    case SIDEKICK_BALL_IDLE:
        sidekickBall_handlePlayerInteraction(obj, state);
        break;
    default:
        break;
    }

    (*gPathControlInterface)->update(obj, state, timeDelta);
    (*gPathControlInterface)->apply(obj, state);
    (*gPathControlInterface)->advance(obj, state, timeDelta);
}

static inline int sidekickBall_updateFloorDepth(GameObject* obj, SidekickBallState* state) {
    if (state->floorHeight > 0.0f) {
        state->floorY = state->floorBaseY;
        state->floorDepth = state->floorHeight;
        return 1;
    }
    if (sidekickBall_floatsNotEqual(state->floorY, 0.0f)) {
        if (obj->anim.localPosY > state->floorY) {
            state->floorY = 0.0f;
        } else {
            state->floorDepth = state->floorY - obj->anim.localPosY;
            return 1;
        }
    }
    return 0;
}

u8 trickyBallMove(GameObject* obj) {
    int hasCollisionNormal;
    Vec collisionNormal;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 speed;
    f32 invSpeed;
    f32 reflectedX;
    f32 reflectedY;
    f32 reflectedZ;
    f32 dot;
    f32 restitution;
    SidekickBallState* state;
    int hasMovementDelta;
    int hasFloorDepth;

    state = obj->extra;
    hasCollisionNormal = 0;
    hasMovementDelta = 0;
    restitution = SIDEKICKBALL_RESTITUTION;
    speed = restitution;

    ObjHits_EnableObject(obj);

    deltaY = (state->previousPosY - obj->anim.localPosY >= 0.0f) ? state->previousPosY - obj->anim.localPosY
                                                                 : -(state->previousPosY - obj->anim.localPosY);
    deltaX = (state->previousPosX - obj->anim.localPosX >= 0.0f) ? state->previousPosX - obj->anim.localPosX
                                                                 : -(state->previousPosX - obj->anim.localPosX);
    deltaZ = (state->previousPosZ - obj->anim.localPosZ >= 0.0f) ? state->previousPosZ - obj->anim.localPosZ
                                                                 : -(state->previousPosZ - obj->anim.localPosZ);

    if ((deltaX + deltaY + deltaZ) < SIDEKICKBALL_MOVEMENT_EPSILON) {
    } else {
        PSVECSubtract(&obj->anim.localPos, (Vec*)&state->previousPosX, &collisionNormal);
        speed = restitution = SIDEKICKBALL_RESTITUTION;
        hasCollisionNormal = 1;
        hasMovementDelta = 1;
    }

    hasFloorDepth = sidekickBall_updateFloorDepth(obj, state);

    if (hasFloorDepth != 0) {
        obj->anim.velocityX *= SIDEKICKBALL_FLOOR_DAMPING;
        obj->anim.velocityY *= SIDEKICKBALL_FLOOR_DAMPING;
        obj->anim.velocityZ *= SIDEKICKBALL_FLOOR_DAMPING;
        obj->anim.velocityY += SIDEKICKBALL_FLOOR_ACCELERATION * timeDelta;
        OSReport(sSidekickBallYVelDepthFormat, obj->anim.velocityY, state->floorDepth);
        if ((obj->anim.velocityY < SIDEKICKBALL_FLOOR_SETTLE_SPEED) &&
            (obj->anim.velocityY > -SIDEKICKBALL_FLOOR_SETTLE_SPEED) &&
            (state->floorDepth < SIDEKICKBALL_FLOOR_SETTLE_DEPTH)) {
            return 1;
        }
    } else if (hasCollisionNormal == 0) {
        obj->anim.velocityY -= SIDEKICKBALL_GRAVITY * timeDelta;
    }

    objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta, obj->anim.velocityZ * timeDelta);
    (*gPathControlInterface)->update(obj, state, timeDelta);
    (*gPathControlInterface)->apply(obj, state);
    (*gPathControlInterface)->advance(obj, state, timeDelta);

    if (state->hasCollisionNormal != 0) {
        hasCollisionNormal = 1;
        collisionNormal.x = state->collisionNormal[0];
        collisionNormal.y = state->collisionNormal[1];
        collisionNormal.z = state->collisionNormal[2];
    }

    if (hasCollisionNormal != 0) {
        PSVECNormalize(&collisionNormal, &collisionNormal);
        reflectedX = -obj->anim.velocityX;
        reflectedY = -obj->anim.velocityY;
        reflectedZ = -obj->anim.velocityZ;
        speed = sqrtf(reflectedX * reflectedX + reflectedY * reflectedY + reflectedZ * reflectedZ);
        if (speed > SIDEKICKBALL_BOUNCE_SOUND_SPEED) {
            Sfx_PlayFromObject(obj, SFXTRIG_baptr1_c);
        }
        if (0.0f != speed) {
            invSpeed = 1.0f / speed;
            reflectedX *= invSpeed;
            reflectedY *= invSpeed;
            reflectedZ *= invSpeed;
        }
        dot = 2.0f * ((reflectedX * collisionNormal.x) + (reflectedY * collisionNormal.y) +
                                  (reflectedZ * collisionNormal.z));
        logPrintf(sSidekickBallDotFormat, dot);
        if (dot > 0.0f) {
            obj->anim.velocityX = collisionNormal.x * dot;
            obj->anim.velocityY = collisionNormal.y * dot;
            obj->anim.velocityZ = collisionNormal.z * dot;
            obj->anim.velocityX -= reflectedX;
            obj->anim.velocityY -= reflectedY;
            obj->anim.velocityZ -= reflectedZ;
            if (sidekickBall_floatsEqual(state->floorY, 0.0f) && (speed < SIDEKICKBALL_STOP_BOUNCING_SPEED) &&
                (state->hasCollisionNormal != 0)) {
                return 2;
            }
            PSVECScale(&obj->anim.velocity, &obj->anim.velocity, speed * restitution);
        }
    }

    if (hasMovementDelta != 0) {
        obj->anim.velocityY -= SIDEKICKBALL_GRAVITY * timeDelta;
    }

    Obj_UpdateRollingRotation(obj);
    state->previousPosX = obj->anim.localPosX;
    state->previousPosY = obj->anim.localPosY;
    state->previousPosZ = obj->anim.localPosZ;
    return 3;
}

void SidekickBall_init(GameObject* obj) {
    u8 pathFlag;
    SidekickBallState* state;
    ObjHitsPriorityState* hitState;

    state = obj->extra;
    pathFlag = SIDEKICKBALL_PATH_FLAG;
    memset(state, 0, sizeof(SidekickBallState));
    Obj_GetPlayerObject();
    state->ballMode = SIDEKICK_BALL_IDLE;
    state->fadeTimer = 0.0f;
    obj->objectFlags |= OBJECT_OBJFLAG_HITDETECT_DISABLED;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    state->primaryRadius = hitState->primaryRadius;
    (*gPathControlInterface)->init(state, 0, SIDEKICKBALL_PATH_CONFIG, 1);
    (*gPathControlInterface)->setLocalPointCollision(state, 1, gSidekickBallPathPointData, &state->primaryRadius, 1);
    (*gPathControlInterface)->setup(state, 1, gSidekickBallPathPointData, &state->primaryRadius, &pathFlag);
    (*gPathControlInterface)->attachObject((void*)obj, state);
    ObjHits_DisableObject(obj);
    state->hittableLatch = 0;
    ObjMsg_AllocQueue((void*)obj, SIDEKICKBALL_MESSAGE_CAPACITY);
    mainSetBits(GAMEBIT_ITEM_TrickyBall_Usable, 0);
}

f32 gSidekickBallPathPointData[3] = {0.0f, 0.0f, 0.0f};

ObjectDescriptor gSidekickBallObjDescriptor = {
    0,                                             /* reserved0 */
    0,                                             /* reserved1 */
    0,                                             /* reserved2 */
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,              /* slotCountAndFlags */
    0,                                             /* initialise */
    0,                                             /* release */
    0,                                             /* slot02 */
    (ObjectDescriptorCallback)SidekickBall_init,   /* init */
    (ObjectDescriptorCallback)SidekickBall_update, /* update */
    0,                                             /* hitDetect */
    (ObjectDescriptorCallback)SidekickBall_render, /* render */
    (ObjectDescriptorCallback)SidekickBall_free,   /* free */
    0,                                             /* getObjectTypeId */
    SidekickBall_getExtraSize,                     /* getExtraSize */
};

char sSidekickBallYVelDepthFormat[] = "yvel %f, depth %f\n";

char sSidekickBallDotFormat[] = " dot %f ";
