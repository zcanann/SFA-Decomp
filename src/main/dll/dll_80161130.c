/*
 * Grimble baddie state-machine handlers plus the ChukChuk ice-spitter and
 * ice-ball object descriptors, and a scarab AI proximity gate.
 *
 * grimble_stateHandler* are the ground-baddie move/anim dispatch handlers
 * (A0x = primary moves, B0x = secondary/transition states), each driving
 * ObjAnim_SetCurrentMove, baddie move/anim speeds, hit-volume registration
 * and the gPlayerInterface / gBaddieControlInterface vtables off the shared
 * GroundBaddieState. scarab_updateProximityGate picks a move via the player
 * vtable[5] based on the signed planar distance to the current target.
 */
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/scarab.h"
#include "main/dll/grimble_state.h"
#include "main/objhits.h"
#include "main/gamebits.h"

extern int randomGetRange(int lo, int hi);
extern void Obj_FreeObject(int* obj);
extern f32 timeDelta;
extern int getAngle(float y, float x);
extern void** gBaddieControlInterface;
extern void** gPlayerInterface;
extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EE8;
extern f32 sqrtf(f32);
extern f32 lbl_803E2EB0;
extern f32 gScarabTargetStandoffDist;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EC0;
extern f32 lbl_803E2EC4;
extern f32 lbl_803E2EC8;
extern f32 lbl_803E2ECC;

void chukchuk_free(void);

void chukchuk_hitDetect(void);

void chukchuk_release(void);

void chukchuk_initialise(void);

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

void chukchuk_init(u8* obj, u8* params);
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

#pragma peephole off
int grimble_stateHandlerB03(int p1, u8* obj)
{
    if ((s8)obj[0x354] < 1) return 5;
    return 1;
}

#pragma scheduling off
int grimble_stateHandlerB05(int* obj, u8* obj2)
{
    GroundBaddieState* x = ((GameObject*)obj)->extra;
    if ((s8)obj2[0x27b] != 0)
    {
        x->unk405 = 0;
        GameBit_Set(x->gameBitB, 0);
        GameBit_Set(x->gameBitA, 1);
    }
    return 0;
}

int grimble_stateHandlerA08(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2EB8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.moveSpeed = lbl_803E2EE8;
    if ((*(int*)&state->baddie.eventFlags & 0x200) != 0)
    {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        *(int*)&state->baddie.eventFlags &= ~0x200;
        ((void(*)(int*, int, int, int))((void**)*gBaddieControlInterface)[19])(obj, sub->triggerId, -1, 1);
    }
    return 0;
}

int grimble_stateHandlerB04(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 8);
        *(int*)&state->baddie.targetObj = 0;
        state->baddie.physicsActive = 0;
        state->baddie.hasTarget = 0;
        ObjHits_DisableObject((int)obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    if (((GameObject*)obj)->anim.alpha == 0)
    {
        if (*(void**)&((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 6;
    }
    return 0;
}

int grimble_stateHandlerB01(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 9);
    }
    if ((s8)state->baddie.moveDone != 0)
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerB00(int obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2ED0;
    extern f32 lbl_803E2ED4;
    u16 a;
    u16 b;
    u16 c;

    if (*(void**)&p->baddie.targetObj != NULL && p->baddie.controlMode != 2)
    {
        if ((f32)p->baddie.stateTimer > lbl_803E2ED0 * timeDelta)
        {
            (*(void (**)(int, int, int, u16*, u16*, u16*))((char*)*gBaddieControlInterface + 0x14))(
                obj, *(int*)&p->baddie.targetObj, 16, &a, &b, &c);
            if (a < 4 || a > 11)
            {
                return 3;
            }
            (*(void (**)(int, u8*, int))((char*)*gPlayerInterface + 0x14))(obj, (u8*)p, 2);
            p->baddie.moveSpeed = lbl_803E2ED4;
            *(s8*)&p->baddie.moveDone = 0;
        }
    }
    return 0;
}

int grimble_stateHandlerA09(int obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EE0;
    extern f32 lbl_803E2EE4;
    GroundBaddieState* sub;
    f32 spd;

    sub = ((GameObject*)obj)->extra;
    *(s8*)&p->baddie.stateTag = 0;
    p->baddie.moveSpeed = lbl_803E2EE0;
    spd = lbl_803E2EB8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        Sfx_PlayFromObject(obj, SFXsc_death02);
        if (*(char*)&p->baddie.moveJustStartedA != '\0')
        {
            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
            *(s8*)&p->baddie.moveDone = 0;
        }
        p->baddie.moveSpeed = lbl_803E2EE4;
        *(s8*)&p->baddie.moveDone = 0;
        ((GameObject*)obj)->anim.alpha = 0xff;
        sub->flags400 |= 0x100;
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA06(int obj, GroundBaddieState* p, f32 spd)
{
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EF4;
    extern f32 lbl_803E2EF8;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = (int)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (randomGetRange(0, 100) < 50)
    {
        if (*(char*)&p->baddie.moveJustStartedA != '\0')
        {
            ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E2EB8, 0);
            *(s8*)&p->baddie.moveDone = 0;
        }
    }
    else if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(short*, u8*, f32, int))((char*)*gPlayerInterface + 0x20))((short*)obj, (u8*)p, spd, 1);
    (*(void (**)(void*, void*, f32))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) + 0x28))(
        *(void**)&((GrimbleControl*)hit)->pathObj, (void*)(hit + 0x48),
        p->baddie.animSpeedA * (f32)(1 - (((GrimbleControl*)hit)->reversed << 1)));
    if (((GrimbleControl*)hit)->pathProgress < lbl_803E2EF4)
    {
        ((GrimbleControl*)hit)->pathProgress = lbl_803E2EF4;
    }
    else if (((GrimbleControl*)hit)->pathProgress > lbl_803E2EF8)
    {
        ((GrimbleControl*)hit)->pathProgress = lbl_803E2EF8;
    }
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, ((GrimbleControl*)hit)->pathProgress - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, lbl_803E2EFC + ((GrimbleControl*)hit)->pathProgress, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleControl*)hit)->reversed << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 5;
    }
    return 0;
}

int grimble_stateHandlerA07(short* obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EEC;
    int hit;
    s16 yaw;
    int diff;
    f32 spd;

    hit = (int)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        Sfx_PlayFromObject(obj, SFXsc_attack04);
    }
    p->baddie.moveSpeed = lbl_803E2EEC;
    yaw = ((GrimbleControl*)hit)->baseRotX;
    diff = *obj - (yaw & 0xffff);
    if (diff > 0x8000)
    {
        diff -= 0xffff;
    }
    if (diff < -0x8000)
    {
        diff += 0xffff;
    }
    *obj = yaw;
    if (diff > 0x3ffc || diff < -0x3ffc)
    {
        *obj += 0x8000;
    }
    spd = lbl_803E2EB8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

int grimble_stateHandlerA05(short* obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = (int)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, ((GrimbleControl*)hit)->pathProgress - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, lbl_803E2EFC + ((GrimbleControl*)hit)->pathProgress, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleControl*)hit)->reversed << 1) - 1);
    }
    return 0;
}

int grimble_stateHandlerA04(short* obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EF0;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = (int)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, ((GrimbleControl*)hit)->pathProgress - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, lbl_803E2EFC + ((GrimbleControl*)hit)->pathProgress, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleControl*)hit)->reversed << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 6;
    }
    return 0;
}

int grimble_stateHandlerA03(short* obj, GroundBaddieState* p)
{
    extern f32 lbl_803E2EE4;
    extern f32 lbl_803E2EFC;
    int hit;
    f64 d;
    f32 r;
    struct
    {
        f32 x, y, z;
    } b;
    struct
    {
        f32 x, y, z;
    } a;

    hit = (int)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2EB8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    p->baddie.moveSpeed = lbl_803E2EE4;
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, ((GrimbleControl*)hit)->pathProgress - lbl_803E2EFC, &a.x, &a.y, &a.z);
    (*(void (**)(void*, f32, f32*, f32*, f32*))(**(int**)(((GrimbleControl*)hit)->pathObj + 0x68) +
        0x24))(
        *(void**)&((GrimbleControl*)hit)->pathObj, lbl_803E2EFC + ((GrimbleControl*)hit)->pathProgress, &b.x, &b.y, &b.z);
    a.x = a.x - b.x;
    a.y = a.y - b.y;
    a.z = a.z - b.z;
    r = sqrtf(a.x * a.x + a.z * a.z);
    d = r;
    a.x = r;
    {
        int ang = (s16)getAngle(a.y, d);
        ((GameObject*)obj)->anim.rotY = ang * ((((GrimbleControl*)hit)->reversed << 1) - 1);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        return 1;
    }
    return 0;
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};

int scarab_updateProximityGate(int* obj, GroundBaddieState* state)
{
    int* target;
    f32 dx;
    f32 dz;
    f32 magAbs;
    u32 rel;

    target = *(int**)&state->baddie.targetObj;
    if (target == NULL)
    {
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        return 1;
    }
    if (state->baddie.controlMode != 6)
    {
        dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)target)->anim.localPosX;
        dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)target)->anim.localPosZ;
        rel = (getAngle(dx, dz) - *(s16*)obj) & 0xffff;
        if (rel > 0x4000 && rel < 0xc000)
        {
            dx = lbl_803E2EB0;
        }
        else
        {
            dx = sqrtf(dx * dx + dz * dz) - gScarabTargetStandoffDist;
        }
        magAbs = dx < lbl_803E2EB8 ? -dx : dx;
        if (magAbs < lbl_803E2EBC)
        {
            if (state->baddie.controlMode == 1 ||
                (state->baddie.controlMode == 5 && (s8)state->baddie.moveDone != 0))
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 6);
                goto post;
            }
        }
        if (state->baddie.controlMode == 1) goto post;
        if (dx > lbl_803E2EC0)
        {
            if (state->baddie.controlMode != 4 &&
                (state->baddie.controlMode != 5 || (s8)state->baddie.moveDone != 0))
            {
                ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
            }
        }
        if (dx < lbl_803E2EC4)
        {
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
        }
    post:
        if (state->baddie.controlMode == 1)
        {
            state->baddie.moveSpeed = (dx > lbl_803E2EB8) ? lbl_803E2EC8 : lbl_803E2ECC;
        }
    }
    return 0;
}
