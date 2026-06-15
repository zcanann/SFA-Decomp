/* DLL 0x00F5 (sidekickball) — Sidekick ball and auto-transporter objects [0x801793A4-0x8017A00C). */
#include "main/dll/dll_00F4_doorf4.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objseq.h"

/*
 * Per-object extra state for the doorf4 auto door
 * (doorf4_getExtraSize == 0x24).
 */
typedef struct DoorF4State
{
    f32 cosYaw; /* cos/sin of spawn yaw; door plane normal */
    f32 sinYaw;
    f32 planeD; /* -(cos*x + sin*z) plane offset */
    f32 openRange; /* per-type approach distance */
    int gameBitA; /* params+0x1E; open latch */
    int gameBitB; /* per-type (68/152/-1) secondary gate */
    int unk18; /* params+0x20 */
    u16 sfxOpen; /* 830 for types 318/890 */
    u16 sfxClose; /* 831 */
    u8 active; /* gamebit-derived open state */
    u8 triggerLatch;
    u8 toggled;
    u8 pad23;
} DoorF4State;

STATIC_ASSERT(sizeof(DoorF4State) == 0x24);

/*
 * Per-object extra state for the sidekick (Tricky) ball
 * (sidekickball_getExtraSize == 0x2CC). Only locally-evidenced
 * fields are named.
 */
#include "main/dll/sidekickball_state.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/dll_00F5_sidekickball.h"
#include "main/dll/tframeanimator_state.h"

typedef struct Doorf4State
{
    u8 pad0[0x1C - 0x0];
    u16 unk1C;
    u8 pad1E[0x24 - 0x1E];
} Doorf4State;

extern undefined4 ObjMsg_SendToObject();

void FUN_80178338(undefined4 param_1);

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E36A0;
extern f32 lbl_803E369C;
extern void getYButtonItem(s16 * out);
extern u32 getButtonsJustPressed(int controller);
extern int fn_80295BF0(int* player);
extern int fn_8029669C(int* player);
extern void vecRotateZXY(void* inParams, f32* outVec);
extern f32 lbl_803E3688;
extern f32 lbl_803E368C;
extern f32 lbl_803E3690;
extern f32 lbl_803E3694;
extern f32 lbl_803E3698;
extern f32 lbl_803E36A4;
extern u32 GameBit_Get(int eventId);
extern f32 mathSinf(f32 x);
extern f32 sqrtf(f32 x);
extern f32 timeDelta;
extern f32 lbl_803E36A8;
extern f32 lbl_803E36AC;
extern u8* getTrickyObject(void);
extern u32 GameBit_Get(int bit);
extern void Obj_FreeObject(u8 * obj);
extern u8 trickyBallMove(u8 * obj);
extern int buttonGetDisabled(int unused);
extern void OSReport(const char* msg, ...);
extern uint GameBit_Get(int eventId);
extern void objMove(int obj, f32 dx, f32 dy, f32 dz);
extern void fn_8002A5DC(int obj);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void fn_80137948(const char* fmt, ...);
extern undefined4 sidekickball_init();
extern f32 lbl_803E36B0;
extern f32 lbl_803E36B4;
extern f32 lbl_803E36B8;
extern f32 lbl_803E36BC;
extern f32 lbl_803E36C0;
extern f32 lbl_803E36C4;
extern f32 lbl_803E36C8;
extern f32 lbl_803E36CC;
extern f32 lbl_803E36D0;
extern f32 lbl_803E36D4;
extern char sSidekickBallYVelDepthFormat[];
extern char sSidekickBallDotFormat[];
extern void* memset(void* dest, int value, u32 size);
extern u32 GameBit_Get(int gameBit);
extern u8 lbl_80320F30[];
extern f32 mathSinf(f32 v);

int sidekickball_getExtraSize(void) { return 0x2cc; }

int fn_801793A4(int* obj) { return *((u8*)((int**)obj)[0xb8 / 4] + 0x274) == 0; }

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
    u8 b = state->ballMode;
    if (b != 3 && b != 2) return;
    state->fadeTimer = lbl_803E369C;
}

int fn_80179650(int* obj)
{
    int r = 0;
    u8 b = (*(SidekickBallState**)&((GameObject*)obj)->extra)->ballMode;
    if (b == 2 || b == 1) r = 1;
    return r;
}

void fn_80179678(int obj)
{
    SidekickBallState* state = ((GameObject*)obj)->extra;
    state->fadeTimer = lbl_803E369C;
    state->ballMode = 0;
    ObjHits_DisableObject(obj);
    state->unk25B = 0;
}

void fn_801796BC(int obj, f32 a, f32 b, f32 c)
{
    SidekickBallState* state = ((GameObject*)obj)->extra;
    state->ballMode = 3;
    state->fadeTimer = lbl_803E369C;
    *(f32*)((char*)obj + 36) = a;
    ((GameObject*)obj)->anim.velocityY = b;
    ((GameObject*)obj)->anim.velocityZ = c;
    ObjHits_EnableObject(obj);
    ObjHits_SyncObjectPositionIfDirty(obj);
    state->unk25B = 1;
    state->launchX = ((GameObject*)obj)->anim.localPosX;
    state->launchY = ((GameObject*)obj)->anim.localPosY;
    state->launchZ = ((GameObject*)obj)->anim.localPosZ;
}

void trickyBallFn_801793b8(int obj, u8* params)
{
    extern void Sfx_PlayFromObject(int obj, int sfxId);
    extern int* Obj_GetPlayerObject(void);
    int* player;
    int* playerState;
    s16 yItem;
    u32 btns;
    f32 lcl[6];

    player = Obj_GetPlayerObject();
    playerState = ((GameObject*)player)->extra;

    if (params[0x2c8] == 1) goto end;

    if (params[0x2c9] == 0)
    {
        params[0x2c9] = 1;
        if (params[0x2c9] == 0) goto end;
        params[0x2ca] = 1;
        goto end;
    }

    ObjHits_DisableObject(obj);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;

    getYButtonItem(&yItem);
    btns = getButtonsJustPressed(0);
    if ((btns & 0x100) != 0 || (yItem == 5 && (getButtonsJustPressed(0) & 0x800) != 0))
    {
        if (fn_80295BF0(player) != 0)
        {
            params[0x2ca] = 0;
        }
        else
        {
            Sfx_PlayFromObject(0, 0x10a);
        }
    }

    if (((GameObject*)obj)->unkF8 == 1)
    {
        params[0x2c9] = 2;
    }
    if (params[0x2c9] != 2) goto end;
    if (((GameObject*)obj)->unkF8 != 0) goto end;

    if (fn_8029669C(player) == 0)
    {
        params[0x2c9] = 0;
        params[0x2ca] = 0;
        *(f32*)((char*)params + 0x26c) = lbl_803E36A4;
        params[0x274] = 5;
        goto end;
    }

    params[0x2c9] = 0;
    params[0x2c8] = 1;

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
    if (((GameObject*)player)->anim.parent != NULL)
    {
        *(s16*)lcl = (s16)(*(s16*)*(int**)&((GameObject*)player)->anim.parent + *(s16*)player);
    }
    else
    {
        *(s16*)lcl = *(s16*)player;
    }
    vecRotateZXY(lcl, &((GameObject*)obj)->anim.velocityX);

    fn_801796BC(obj,
                ((GameObject*)obj)->anim.velocityX,
                ((GameObject*)obj)->anim.velocityY,
                ((GameObject*)obj)->anim.velocityZ);

end:
    if (params[0x2ca] != 0)
    {
        ObjMsg_SendToObject(player, 0x100010, (void*)obj, 0);
    }
}

enum SidekickBallMode
{
    SIDEKICK_BALL_IDLE = 0,
    SIDEKICK_BALL_MOVING = 1,
    SIDEKICK_BALL_HELD = 2,
    SIDEKICK_BALL_THROWN = 3,
    SIDEKICK_BALL_FADING = 5,
};

void sidekickball_update(u8* self)
{
    extern int ObjTrigger_IsSet(u8 * obj);
    extern void trickyBallFn_801793b8(int obj, u8 *state);
    extern u8* Obj_GetPlayerObject(void);
    SidekickBallState* state;
    u8* player;
    u8* other;
    u32 otherStatusZeroWord;
    int otherStatusMask;
    int gotHit;

    state = (SidekickBallState*)*(int*)&((GameObject*)self)->extra;
    self[0xAF] = (u8)(self[0xAF] | 0x8);
    state->onPathPoint = 0;

    player = Obj_GetPlayerObject();
    other = getTrickyObject();
    if (player == NULL
        || (*(u16*)(player + 0xB0) & 0x1000) != 0
        || other == NULL
        || (otherStatusZeroWord = (u32)__cntlzw((u32) * (u16*)(other + 0xB0)),
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
        if (state->fadeTimer >= lbl_803E36A8)
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
        self[0xAF] = (u8)(self[0xAF] & ~0x8);
        gotHit = 0;
        if ((buttonGetDisabled(0) & 0x100) == 0u
            && ((GameObject*)self)->unkF8 == 0
            && ObjTrigger_IsSet(self) != 0)
        {
            ObjHits_DisableObject((u32)self);
            gotHit = 1;
        }
        state->triggerHit = (u8)gotHit;
        if (state->triggerHit != 0)
        {
            state->triggerArmed = 0;
            state->triggerHit = 0;
            state->ballMode = SIDEKICK_BALL_IDLE;
        }
        break;
    case SIDEKICK_BALL_FADING:
        state->fadeTimer = state->fadeTimer + timeDelta;
        if (state->fadeTimer >= *(f32*)&lbl_803E36A4)
        {
            Obj_FreeObject(self);
            return;
        }
        {
            f32 v = lbl_803E36AC * state->fadeTimer / lbl_803E36A4;
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
    extern void Sfx_PlayFromObject(int obj, u16 sfxId);
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
    int hasCollisionNormal;
    int movedFromCache;
    int hasFloorDepth;

    state = ((GameObject*)obj)->extra;
    hasCollisionNormal = 0;
    movedFromCache = 0;
    speed = lbl_803E36B0;

    ObjHits_EnableObject((u32)obj);

    dy = state->prevPos[1] - ((GameObject*)obj)->anim.localPosY;
    dy = (dy >= lbl_803E369C) ? dy : -dy;
    dx = state->prevPos[0] - ((GameObject*)obj)->anim.localPosX;
    dx = (dx >= lbl_803E369C) ? dx : -dx;
    dz = state->prevPos[2] - ((GameObject*)obj)->anim.localPosZ;
    dz = (dz >= lbl_803E369C) ? dz : -dz;

    if ((dx + dy + dz) >= lbl_803E36B4)
    {
        PSVECSubtract((f32*)(obj + 0x0c), state->prevPos, collisionNormal);
        speed = lbl_803E36B0;
        hasCollisionNormal = 1;
        movedFromCache = 1;
    }

    if (state->floorHeight > lbl_803E369C)
    {
        state->floorY = state->floorBaseY;
        state->floorDepth = state->floorHeight;
        hasFloorDepth = 1;
    }
    else if (state->floorY != lbl_803E369C)
    {
        if (((GameObject*)obj)->anim.localPosY > state->floorY)
        {
            state->floorY = lbl_803E369C;
            hasFloorDepth = 0;
        }
        else
        {
            state->floorDepth = state->floorY - ((GameObject*)obj)->anim.localPosY;
            hasFloorDepth = 1;
        }
    }
    else
    {
        hasFloorDepth = 0;
    }

    if (hasFloorDepth != 0)
    {
        ((GameObject*)obj)->anim.velocityX *= lbl_803E36B8;
        ((GameObject*)obj)->anim.velocityY *= lbl_803E36B8;
        ((GameObject*)obj)->anim.velocityZ *= lbl_803E36B8;
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
        ((GameObject*)obj)->anim.velocityY -= lbl_803E36C8 * timeDelta;
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
            Sfx_PlayFromObject((int)obj, 0x16c);
        }
        if (speed != lbl_803E369C)
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
            ((GameObject*)obj)->anim.velocityX = (collisionNormal[0] * dot) - reflectedX;
            ((GameObject*)obj)->anim.velocityY = (collisionNormal[1] * dot) - reflectedY;
            ((GameObject*)obj)->anim.velocityZ = (collisionNormal[2] * dot) - reflectedZ;
            if ((state->floorY == lbl_803E369C) && (speed < lbl_803E36D4) &&
                (state->hasCollisionNormal != 0))
            {
                return 2;
            }
            PSVECScale((f32*)(obj + 0x24), (f32*)(obj + 0x24), speed * lbl_803E36B0);
        }
    }

    if (movedFromCache != 0)
    {
        ((GameObject*)obj)->anim.velocityY -= lbl_803E36C8 * timeDelta;
    }

    fn_8002A5DC((int)obj);
    state->prevPos[0] = ((GameObject*)obj)->anim.localPosX;
    state->prevPos[1] = ((GameObject*)obj)->anim.localPosY;
    state->prevPos[2] = ((GameObject*)obj)->anim.localPosZ;
    return 3;
}

typedef struct LevelnameState
{
    u8 pad0[0x8 - 0x0];
    s32 unk8;
    u8 padC[0xE - 0xC];
    s16 unkE;
    s16 unk10;
    s16 unk12;
    u8 pad14[0x18 - 0x14];
} LevelnameState;

undefined4 sidekickball_init(int obj)
{
    extern undefined4 ObjMsg_AllocQueue();
    extern void GameBit_Set(int gameBit, int value);
    extern int* Obj_GetPlayerObject(void);
    u8 pathFlag;
    u8* state;
    int objDef;

    state = ((GameObject*)obj)->extra;
    pathFlag = 5;
    memset(state, 0, 0x2cc);
    Obj_GetPlayerObject();
    state[0x274] = 0;
    ((TFrameAnimatorState*)state)->unk26C = lbl_803E369C;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    objDef = *(int*)&((GameObject*)obj)->anim.hitReactState;
    ((TFrameAnimatorState*)state)->primaryRadius = (f32)((ObjHitsPriorityState*)objDef)->primaryRadius;
    (*gPathControlInterface)->init(state, 0, 0x40007, 1);
    (*gPathControlInterface)->setLocalPointCollision(state, 1, lbl_80320F30, state + 0x268, 1);
    (*gPathControlInterface)->setup(state, 1, lbl_80320F30, state + 0x268, &pathFlag);
    (*gPathControlInterface)->attachObject((void*)obj, state);
    ObjHits_DisableObject((u32)obj);
    state[0x25b] = 0;
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

void levelname_free(void);

void levelname_render(void);

void levelname_hitDetect(void);

void levelname_release(void);

void levelname_initialise(void);

void levelname_update(int* obj);

void ProjectileSwitch_free(void);

int levelname_getExtraSize(void);
int levelname_getObjectTypeId(void);
int ProjectileSwitch_getExtraSize(void);

int ProjectileSwitch_getObjectTypeId(int* obj);

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
