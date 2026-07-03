/*
 * DLL 0x00F5 (sidekickball) - the Tricky "fetch" ball.
 *
 * sidekickball_init spawns one ball object (extra size 0x2CC), wires it
 * onto the path-control interface and clears game bit 0x3F8; the free
 * callback re-sets 0x3F8 so the spawner knows the ball is gone.
 *
 * sidekickball_update runs the ball through a small mode machine
 * (SidekickBallMode): IDLE waits for the player to grab/charge a throw
 * (trickyBallFn_801793b8), THROWN/MOVING fly the ball with bounce +
 * floor-depth physics and surface reflection (trickyBallMove), and
 * FADING ramps alpha to 0 before freeing. The ball self-frees if the
 * player or Tricky is missing/dead or game bit 0xD00 is set.
 *
 * gAreaObjDescriptor is an unrelated "area" object table built from
 * external area_* callbacks.
 */
#include "main/dll/dll_00F4_doorf4.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/sidekickball_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/tframeanimator_state.h"
#include "main/objlib.h"
#include "main/pad.h"
#include "main/dll/dll_00F5_sidekickball.h"
#include "string.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
extern void objRenderFn_8003b8f4(f32);
extern const f32 lbl_803E369C;
extern const f32 lbl_803E36A0;
extern f32 gSidekickBallFadeDuration;
extern const f32 gSidekickBallActiveTimeout;
extern const f32 gSidekickBallMaxAlpha;
extern u16 getYButtonItem(s16* out);
extern int fn_80295BF0(int* player);
extern int fn_8029669C(int* player);
extern void vecRotateZXY(void* inParams, f32* outVec);
extern const f32 lbl_803E3688;
extern const f32 lbl_803E368C;
extern const f32 lbl_803E3690;
extern const f32 lbl_803E3694;
extern const f32 lbl_803E3698;
extern u32 GameBit_Get(int eventId);
extern f32 sqrtf(f32 x);
extern f32 timeDelta;
extern void* getTrickyObject(void);
extern void Obj_FreeObject(u8* obj);
extern u32 buttonGetDisabled(int port);
extern void OSReport(const char* msg, ...);
extern void objMove(int obj, f32 dx, f32 dy, f32 dz);
extern void fn_8002A5DC(int obj);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void fn_80137948(char* fmt, ...);
extern const f32 gSidekickBallRestitution;
extern const f32 lbl_803E36B4;
extern const f32 gSidekickBallFloorDamping;
extern const f32 lbl_803E36BC;
extern const f32 lbl_803E36C0;
extern const f32 lbl_803E36C4;
extern const f32 gSidekickBallGravity;
extern const f32 lbl_803E36CC;
extern const f32 lbl_803E36D0;
extern const f32 lbl_803E36D4;
extern char sSidekickBallYVelDepthFormat[];
extern char sSidekickBallDotFormat[];
extern u8 gSidekickBallPathPointData[];
extern void* Obj_GetPlayerObject(void);

enum SidekickBallMode
{
    SIDEKICK_BALL_IDLE = 0,
    SIDEKICK_BALL_MOVING = 1,
    SIDEKICK_BALL_HELD = 2,
    SIDEKICK_BALL_THROWN = 3,
    SIDEKICK_BALL_FADING = 5,
};

int sidekickball_getExtraSize(void) { return 0x2cc; }

int fn_801793A4(int* obj) { return *((u8*)(int*)((GameObject*)obj)->extra + 0x274) == 0; }

void sidekickball_free(int obj) { GameBit_Set(0x3F8, 1); }

void sidekickball_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (((GameObject*)obj)->unkF8 == 0 || visible == -1)
    {
        objRenderFn_8003b8f4(lbl_803E36A0);
    }
}

void fn_8017962C(int* obj)
{
    SidekickBallState* state = ((GameObject*)obj)->extra;
    u8 mode = state->ballMode;
    if (mode != SIDEKICK_BALL_THROWN && mode != SIDEKICK_BALL_HELD) return;
    state->fadeTimer = lbl_803E369C;
}

int fn_80179650(int* obj)
{
    int result = 0;
    u8 mode = (*(SidekickBallState**)&((GameObject*)obj)->extra)->ballMode;
    if (mode == SIDEKICK_BALL_HELD || mode == SIDEKICK_BALL_MOVING) result = 1;
    return result;
}

void fn_80179678(int obj)
{
    SidekickBallState* state = ((GameObject*)obj)->extra;
    state->fadeTimer = lbl_803E369C;
    state->ballMode = SIDEKICK_BALL_IDLE;
    ObjHits_DisableObject(obj);
    state->hittableLatch = 0;
}

void fn_801796BC(GameObject* obj, f32 a, f32 b, f32 c)
{
    SidekickBallState* state = obj->extra;
    int objId;
    state->ballMode = SIDEKICK_BALL_THROWN;
    state->fadeTimer = lbl_803E369C;
    *(f32*)((char*)obj + 36) = a;
    obj->anim.velocityY = b;
    obj->anim.velocityZ = c;
    ObjHits_EnableObject(objId = (int)obj);
    ObjHits_SyncObjectPositionIfDirty(objId);
    state->hittableLatch = 1;
    state->launchX = obj->anim.localPosX;
    state->launchY = obj->anim.localPosY;
    state->launchZ = obj->anim.localPosZ;
}

void trickyBallFn_801793b8(int obj, u8* paramsRaw)
{

    SidekickBallState* params = (SidekickBallState*)paramsRaw;
    int* player;
    int* playerState;
    s16 yItem;
    u32 btns;
    f32 lcl[6];

    player = Obj_GetPlayerObject();
    playerState = ((GameObject*)player)->extra;

    if (params->triggerArmed == 1) return;

    if (params->triggerHit == 0)
    {
        params->triggerHit = 1;
        if (params->triggerHit == 0) return;
        params->pad2CA[0] = 1;
        return;
    }

    ObjHits_DisableObject(obj);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;

    getYButtonItem(&yItem);
    btns = getButtonsJustPressed(0);
    if ((btns & 0x100) != 0 || (yItem == 5 && (getButtonsJustPressed(0) & 0x800) != 0))
    {
        if (fn_80295BF0(player) != 0)
        {
            params->pad2CA[0] = 0;
        }
        else
        {
            Sfx_PlayFromObject(0, 0x10a);
        }
    }

    if (((GameObject*)obj)->unkF8 == 1)
    {
        params->triggerHit = 2;
    }
    if (params->triggerHit != 2) goto end;
    if (((GameObject*)obj)->unkF8 != 0) goto end;

    if (fn_8029669C(player) == 0) goto fading;

    params->triggerHit = 0;
    params->triggerArmed = 1;

    {
        f32 k = lbl_803E3688;
        ((GameObject*)obj)->anim.velocityY =
            k * (lbl_803E3690 * *(f32*)((char*)playerState + 0x298) + lbl_803E368C);
        ((GameObject*)obj)->anim.velocityZ =
            k * (lbl_803E3698 * *(f32*)((char*)playerState + 0x298) + lbl_803E3694);
    }

    ((GameObject*)lcl)->anim.localPosX = lbl_803E369C;
    ((GameObject*)lcl)->anim.localPosY = lbl_803E369C;
    ((GameObject*)lcl)->anim.localPosZ = lbl_803E369C;
    ((GameObject*)lcl)->anim.rootMotionScale = lbl_803E36A0;
    ((GameObject*)lcl)->anim.rotZ = 0;
    ((GameObject*)lcl)->anim.rotY = 0;
    {
        s16 rotVal;
        if (((GameObject*)player)->anim.parent != NULL)
        {
            rotVal = (s16)(*(s16*)*(int**)&((GameObject*)player)->anim.parent + ((GameObject*)player)->anim.rotX);
        }
        else
        {
            rotVal = ((GameObject*)player)->anim.rotX;
        }
        *(s16*)lcl = rotVal;
    }
    vecRotateZXY(lcl, &((GameObject*)obj)->anim.velocityX);

    fn_801796BC((GameObject*)obj, *(f32*)((char*)obj + 36), ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);
    goto end;

fading:
    params->triggerHit = 0;
    params->pad2CA[0] = 0;
    params->fadeTimer = gSidekickBallFadeDuration;
    params->ballMode = SIDEKICK_BALL_FADING;

end:
    if (params->pad2CA[0] != 0)
    {
        ObjMsg_SendToObject(player, 0x100010, (void*)obj, 0);
    }
}

void sidekickball_update(u8* self)
{
    extern int ObjTrigger_IsSet(u8 * obj);
    extern void trickyBallFn_801793b8(int obj, u8 *state);
    SidekickBallState* state;
    u8* player;
    u8* other;
    u32 otherStatusZeroWord;
    int otherStatusMask;
    int gotHit;

    state = (SidekickBallState*)*(int*)&((GameObject*)self)->extra;
    *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)self)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    state->onPathPoint = 0;

    player = Obj_GetPlayerObject();
    other = getTrickyObject();
    if (player == NULL
        || (((GameObject*)player)->objectFlags & 0x1000) != 0
        || other == NULL
        || (otherStatusZeroWord = __cntlzw((u32)((GameObject*)other)->objectFlags),
            otherStatusMask = otherStatusZeroWord >> 5,
            (otherStatusMask & 0x1000) != 0)
        || GameBit_Get(0xD00) != 0)
    {
        Obj_FreeObject(self);
        return;
    }

    if (state->ballMode == SIDEKICK_BALL_THROWN ||
        state->ballMode == SIDEKICK_BALL_HELD ||
        state->ballMode == SIDEKICK_BALL_MOVING)
    {
        state->fadeTimer = state->fadeTimer + timeDelta;
        if (state->fadeTimer >= gSidekickBallActiveTimeout)
        {
            state->fadeTimer = lbl_803E369C;
            state->ballMode = SIDEKICK_BALL_FADING;
        }
    }

    switch (state->ballMode)
    {
    case SIDEKICK_BALL_THROWN:
        state->ballMode = trickyBallMove(self);
        return;
    case SIDEKICK_BALL_MOVING:
        trickyBallMove(self);
    case SIDEKICK_BALL_HELD:
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode =
            (u8)(*(u8*)&((GameObject*)self)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        gotHit = 0;
        if ((buttonGetDisabled(0) & 0x100) == 0u
            && ((GameObject*)self)->unkF8 == 0
            && ObjTrigger_IsSet(self) != 0)
        {
            ObjHits_DisableObject((u32)self);
            gotHit = 1;
        }
        state->triggerHit = gotHit;
        if (state->triggerHit != 0)
        {
            state->triggerArmed = 0;
            state->triggerHit = 0;
            state->ballMode = SIDEKICK_BALL_IDLE;
        }
        break;
    case SIDEKICK_BALL_FADING:
        state->fadeTimer = state->fadeTimer + timeDelta;
        if (state->fadeTimer >= *(f32*)&gSidekickBallFadeDuration)
        {
            Obj_FreeObject(self);
            return;
        }
        {
            f32 v = gSidekickBallMaxAlpha * state->fadeTimer / gSidekickBallFadeDuration;
            ((GameObject*)self)->anim.alpha = (u8)(0xFF - (int)v);
        }
        break;
    case SIDEKICK_BALL_IDLE:
        trickyBallFn_801793b8((int)self, (u8*)state);
        break;
    default:
        break;
    }

    (*gPathControlInterface)->update(self, state, timeDelta);
    (*gPathControlInterface)->apply(self, state);
    (*gPathControlInterface)->advance(self, state, timeDelta);
}

typedef struct TrickyBallState
{
    u8 pad00[0x68];
    f32 collisionNormal[3];
    u8 pad74[0x1B4 - 0x74];
    f32 floorHeight;
    u8 pad1B8[0x1BC - 0x1B8];
    f32 floorBaseY;
    u8 pad1C0[0x261 - 0x1C0];
    s8 hasCollisionNormal;
    u8 pad262[0x2B0 - 0x262];
    f32 prevPos[3];
    u8 pad2BC[0x2C0 - 0x2BC];
    f32 floorY;
    f32 floorDepth;
} TrickyBallState;

u8 trickyBallMove(u8* obj)
{

    TrickyBallState* state;
    f32 collisionNormal[3];
    f32 dx;
    f32 dy;
    f32 dz;
    f32 speed;
    f32 invSpeed;
    f32 reflectedX;
    f32 reflectedY;
    f32 reflectedZ;
    f32 dot;
    f32 restitution;
    int hasCollisionNormal;
    int movedFromCache;
    int hasFloorDepth;

    state = ((GameObject*)obj)->extra;
    hasCollisionNormal = 0;
    movedFromCache = 0;
    restitution = gSidekickBallRestitution;
    speed = restitution;

    ObjHits_EnableObject((u32)obj);

    dy = (state->prevPos[1] - ((GameObject*)obj)->anim.localPosY >= 0.0f)
             ? state->prevPos[1] - ((GameObject*)obj)->anim.localPosY
             : -(state->prevPos[1] - ((GameObject*)obj)->anim.localPosY);
    dx = (state->prevPos[0] - ((GameObject*)obj)->anim.localPosX >= 0.0f)
             ? state->prevPos[0] - ((GameObject*)obj)->anim.localPosX
             : -(state->prevPos[0] - ((GameObject*)obj)->anim.localPosX);
    dz = (state->prevPos[2] - ((GameObject*)obj)->anim.localPosZ >= 0.0f)
             ? state->prevPos[2] - ((GameObject*)obj)->anim.localPosZ
             : -(state->prevPos[2] - ((GameObject*)obj)->anim.localPosZ);

    if ((dx + dy + dz) < lbl_803E36B4)
    {
    }
    else
    {
        PSVECSubtract((f32*)(obj + 0x0c), state->prevPos, collisionNormal);
        speed = restitution = gSidekickBallRestitution;
        hasCollisionNormal = 1;
        movedFromCache = 1;
    }

    if (state->floorHeight > *(f32*)&lbl_803E369C)
    {
        state->floorY = state->floorBaseY;
        state->floorDepth = state->floorHeight;
        hasFloorDepth = 1;
    }
    else
    {
        if (state->floorY != lbl_803E369C)
        {
            if (((GameObject*)obj)->anim.localPosY > state->floorY)
            {
                state->floorY = lbl_803E369C;
            }
            else
            {
                state->floorDepth = state->floorY - ((GameObject*)obj)->anim.localPosY;
                hasFloorDepth = 1;
                goto floor_done;
            }
        }
        hasFloorDepth = 0;
    floor_done:;
    }

    if (hasFloorDepth != 0)
    {
        ((GameObject*)obj)->anim.velocityX *= gSidekickBallFloorDamping;
        ((GameObject*)obj)->anim.velocityY *= gSidekickBallFloorDamping;
        ((GameObject*)obj)->anim.velocityZ *= gSidekickBallFloorDamping;
        ((GameObject*)obj)->anim.velocityY += lbl_803E36BC * timeDelta;
        OSReport(sSidekickBallYVelDepthFormat, ((GameObject*)obj)->anim.velocityY, state->floorDepth);
        if ((((GameObject*)obj)->anim.velocityY < lbl_803E36C0) &&
            (((GameObject*)obj)->anim.velocityY > lbl_803E36C4) &&
            (state->floorDepth < lbl_803E36A0))
        {
            return 1;
        }
    }
    else if (hasCollisionNormal == 0)
    {
        ((GameObject*)obj)->anim.velocityY -= gSidekickBallGravity * timeDelta;
    }

    objMove((int)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);
    (*gPathControlInterface)->update(obj, state, timeDelta);
    (*gPathControlInterface)->apply(obj, state);
    (*gPathControlInterface)->advance(obj, state, timeDelta);

    if (state->hasCollisionNormal != 0)
    {
        hasCollisionNormal = 1;
        collisionNormal[0] = state->collisionNormal[0];
        collisionNormal[1] = state->collisionNormal[1];
        collisionNormal[2] = state->collisionNormal[2];
    }

    if (hasCollisionNormal != 0)
    {
        PSVECNormalize(collisionNormal, collisionNormal);
        reflectedX = -((GameObject*)obj)->anim.velocityX;
        reflectedY = -((GameObject*)obj)->anim.velocityY;
        reflectedZ = -((GameObject*)obj)->anim.velocityZ;
        speed = sqrtf(reflectedX * reflectedX + reflectedY * reflectedY + reflectedZ * reflectedZ);
        if (speed > lbl_803E36CC)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baptr1_c);
        }
        if (lbl_803E369C != speed)
        {
            invSpeed = lbl_803E36A0 / speed;
            reflectedX *= invSpeed;
            reflectedY *= invSpeed;
            reflectedZ *= invSpeed;
        }
        dot = lbl_803E36D0 *
        ((reflectedX * collisionNormal[0]) + (reflectedY * collisionNormal[1]) +
            (reflectedZ * collisionNormal[2]));
        fn_80137948(sSidekickBallDotFormat, dot);
        if (dot > lbl_803E369C)
        {
            ((GameObject*)obj)->anim.velocityX = collisionNormal[0] * dot;
            ((GameObject*)obj)->anim.velocityY = collisionNormal[1] * dot;
            ((GameObject*)obj)->anim.velocityZ = collisionNormal[2] * dot;
            ((GameObject*)obj)->anim.velocityX -= reflectedX;
            ((GameObject*)obj)->anim.velocityY -= reflectedY;
            ((GameObject*)obj)->anim.velocityZ -= reflectedZ;
            if ((state->floorY == lbl_803E369C) && (speed < lbl_803E36D4) &&
                (state->hasCollisionNormal != 0))
            {
                return 2;
            }
            PSVECScale((f32*)(obj + 0x24), (f32*)(obj + 0x24), speed * restitution);
        }
    }

    if (movedFromCache != 0)
    {
        ((GameObject*)obj)->anim.velocityY -= gSidekickBallGravity * timeDelta;
    }

    fn_8002A5DC((int)obj);
    state->prevPos[0] = ((GameObject*)obj)->anim.localPosX;
    state->prevPos[1] = ((GameObject*)obj)->anim.localPosY;
    state->prevPos[2] = ((GameObject*)obj)->anim.localPosZ;
    return 3;
}

void sidekickball_init(int obj)
{

    extern void GameBit_Set(int eventId, int value);
    u8 pathFlag;
    u8* state;
    int objDef;

    state = ((GameObject*)obj)->extra;
    pathFlag = 5;
    memset(state, 0, 0x2cc);
    Obj_GetPlayerObject(); /* result discarded; the call is emitted in the target */
    ((SidekickBallState*)state)->ballMode = SIDEKICK_BALL_IDLE; /* explicit post-memset store in target */
    ((TFrameAnimatorState*)state)->fadeTimer = lbl_803E369C;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    objDef = *(int*)&((GameObject*)obj)->anim.hitReactState;
    ((TFrameAnimatorState*)state)->primaryRadius = (f32)((ObjHitsPriorityState*)objDef)->primaryRadius;
    (*gPathControlInterface)->init(state, 0, 0x40007, 1);
    (*gPathControlInterface)->setLocalPointCollision(state, 1, gSidekickBallPathPointData, state + 0x268, 1);
    (*gPathControlInterface)->setup(state, 1, gSidekickBallPathPointData, state + 0x268, &pathFlag);
    (*gPathControlInterface)->attachObject((void*)obj, state);
    ObjHits_DisableObject((u32)obj);
    ((SidekickBallState*)state)->hittableLatch = 0; /* explicit post-memset store in target */
    ObjMsg_AllocQueue((void*)obj, 1);
    GameBit_Set(0x3f8, 0);
}

int area_getExtraSize(void);
int area_getObjectTypeId(void);
void area_free(void);
void area_render(void);
void area_hitDetect(void);
void area_update(void);
void area_init(u16* obj);
void area_release(void);
void area_initialise(void);

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};
