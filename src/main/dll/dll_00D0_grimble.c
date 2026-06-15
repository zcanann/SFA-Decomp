#include "main/game_object.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/effect_interfaces.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"

typedef struct GrimblePlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
} GrimblePlacement;

typedef struct GrimbleState
{
    u8 pad0[0x27A - 0x0];
    s8 unk27A;
    u8 pad27B[0x2A0 - 0x27B];
    f32 unk2A0;
    u8 pad2A4[0x314 - 0x2A4];
    s32 unk314;
    u8 pad318[0x346 - 0x318];
    u8 unk346;
    u8 pad347[0x3E8 - 0x347];
    f32 unk3E8;
    u8 pad3EC[0x400 - 0x3EC];
    u16 unk400;
    u8 pad402[0x405 - 0x402];
    u8 unk405;
    u8 pad406[0x40C - 0x406];
    void* unk40C;
    u8 pad410[0x46C - 0x410];
} GrimbleState;

extern undefined4 FUN_80006824();
extern int FUN_80017730();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_800305f8();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3b70;
extern f64 DOUBLE_803e3ba8;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B88;
extern f32 lbl_803E3B8C;
extern f32 lbl_803E3B90;
extern f32 lbl_803E3B94;
extern f32 lbl_803E3B98;
extern f32 lbl_803E3B9C;
extern f32 lbl_803E3BA0;
extern f32 lbl_803E3BA4;
extern f32 lbl_803E3BB0;
extern f32 lbl_803E3BB4;

extern int getAngle(f32 dx, f32 dz);
extern void* Obj_GetPlayerObject(void);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern void* gPlayerInterface;
extern void* gBaddieControlInterface;
extern int lbl_803200E0[];
extern int lbl_80320158[];
extern void objRenderFn_8003b8f4(f32);
extern void* gGrimbleStateHandlersA[11];
extern void* gGrimbleStateHandlersB[6];
int grimble_animEventCallback(void);
void fn_801627F4(int obj);

extern f32 lbl_803E2EB8;
extern f32 lbl_803E2EBC;
extern f32 lbl_803E2EF0;
extern f32 lbl_803E2EF4;
extern f32 lbl_803E2EF8;
extern f32 lbl_803E2EFC;
extern f32 lbl_803E2F00;
extern f32 lbl_803E2F04;
extern f32 lbl_803E2F08;
extern f32 lbl_803E2F0C;
extern f32 lbl_803E2F18;
extern f32 lbl_803E2F1C;
extern f32 lbl_803E2F20;
extern f32 lbl_803E2F24;
extern f32 lbl_803E2F28;

extern void* ObjGroup_GetObjects(int type, int* outCount);

int grimble_stateHandlerA02(int obj, char* state, f32 arg)
{
    extern double sqrtf(double x); /* #57 */
    u16 zone;
    u16 pad;
    u16 dist;
    f32 z2, y2, x2, z, y, x;
    f32 f;
    f32 spd;
    f32 vel;
    s16 angle;
    double d;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 9);
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        ((GroundBaddieState*)state)->baddie.animSpeedA * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1)));
    if (((GrimbleControl*)sub)->unk48 < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF4;
    }
    else if (((GrimbleControl*)sub)->unk48 > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF8;
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->unk48 - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->unk48, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    d = sqrtf(x * x + z * z);
    x = d;
    angle = getAngle(y, (f32)d);
    ((GameObject*)obj)->anim.rotY = (lbl_803E2EBC - lbl_803E2F00 * ((GameObject*)obj)->anim.currentMoveProgress) *
        (f32)(s16)(angle * ((((GrimbleControl*)sub)->reversed << 1) - 1));
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        (*(void (**)(int, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
            obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
        ((GrimbleControl*)sub)->reversed = 1 - *(u8*)&((GrimbleControl*)sub)->reversed;
        ((GameObject*)obj)->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed << 15);
        spd = (f32)(int)
        randomGetRange(0x32, 0x64) / lbl_803E2F04;
        vel = (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) * spd;
        if (zone < 4 || zone > 0xb)
        {
            if (dist > 0x1f4)
            {
                vel *= lbl_803E2EBC + (f32)dist / lbl_803E2F04;
            }
            else
            {
                vel *= lbl_803E2EBC + (f32)dist / lbl_803E2F08;
            }
        }
        ((GrimbleControl*)sub)->targetProgress = ((GrimbleControl*)sub)->unk48 - vel;
        f = ((GrimbleControl*)sub)->targetProgress;
        if (f > lbl_803E2EBC)
        {
        }
        else
        {
            f = lbl_803E2EBC;
        }
        ((GrimbleControl*)sub)->targetProgress = f;
        f = ((GrimbleControl*)sub)->targetProgress;
        if (f < lbl_803E2F0C)
        {
        }
        else
        {
            f = lbl_803E2F0C;
        }
        ((GrimbleControl*)sub)->targetProgress = f;
        return 4;
    }
    return 0;
}

int grimble_stateHandlerA01(int obj, char* state, f32 arg)
{
    extern double sqrtf(double x); /* #57 */
    extern void Sfx_PlayFromObject(int obj, u16 sfxId); /* #57 */
    f32 z2, y2, x2, z, y, x;
    u8 hitEdge;
    s16 angle;
    double d;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 0);
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags
            & ~1;
        Sfx_PlayFromObject(obj, SFXsc_death01);
    }
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        lbl_803E2F18 * (((GroundBaddieState*)state)->baddie.moveSpeed * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1))));
    if (((GrimbleControl*)sub)->unk48 < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF4;
        hitEdge = 1;
    }
    else if (((GrimbleControl*)sub)->unk48 > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF8;
        hitEdge = 1;
    }
    else
    {
        hitEdge = 0;
    }
    if (hitEdge != 0)
    {
        return 7;
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->unk48 - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->unk48, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    d = sqrtf(x * x + z * z);
    x = d;
    angle = getAngle(y, (f32)d);
    ((GameObject*)obj)->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}

int grimble_stateHandlerA00(int obj, char* state, f32 arg)
{
    extern double sqrtf(double x); /* #57 */
    extern void Sfx_PlayFromObject(int obj, u16 sfxId); /* #57 */
    u16 zone;
    u16 pad;
    u16 dist;
    f32 z2, y2, x2, z, y, x;
    s16 angle;
    double d;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2EB8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2EF0;
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 1);
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        ((GroundBaddieState*)state)->baddie.animSpeedA * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1)));
    if (((GrimbleControl*)sub)->unk48 < lbl_803E2EF4)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF4;
    }
    else if (((GrimbleControl*)sub)->unk48 > lbl_803E2EF8)
    {
        ((GrimbleControl*)sub)->unk48 = lbl_803E2EF8;
    }
    (*(void (**)(int, int, int, u16*, u16*, u16*))(*(int*)gBaddieControlInterface + 0x14))(
        obj, *(int*)&((GroundBaddieState*)state)->baddie.targetObj, 0x10, &zone, &pad, &dist);
    if (zone > 3 && zone < 0xc && dist > 0x190 && ((GrimbleControl*)sub)->unk48 > lbl_803E2F00 &&
        ((GrimbleControl*)sub)->unk48 < lbl_803E2F1C)
    {
        return 3;
    }
    if ((((GrimbleControl*)sub)->reversed ^ (((GrimbleControl*)sub)->unk48 >= ((GrimbleControl*)sub)->targetProgress))
        != 0 &&
        *(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        return 3;
    }
    if ((*(int*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        *(int*)&((GroundBaddieState*)state)->baddie.eventFlags = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags
            & ~1;
        Sfx_PlayFromObject(obj, SFXsc_death01);
    }
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->unk48 - lbl_803E2EFC, &x, &y, &z);
    (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
        ((GrimbleControl*)sub)->pathObj, lbl_803E2EFC + ((GrimbleControl*)sub)->unk48, &x2, &y2, &z2);
    x = x - x2;
    y = y - y2;
    z = z - z2;
    d = sqrtf(x * x + z * z);
    x = d;
    angle = getAngle(y, (f32)d);
    ((GameObject*)obj)->anim.rotY = angle * ((((GrimbleControl*)sub)->reversed << 1) - 1);
    return 0;
}

void fn_801627F4(int obj)
{
    int count;
    f32 dist;
    f32 hitY;
    f32 unk;
    f32 f;
    int* ptr;
    int i;
    int diff;
    int facing;
    char* state;
    char* sub;

    state = ((GameObject*)obj)->extra;
    ptr = (int*)ObjGroup_GetObjects(0x17, &count);
    if (count != 0)
    {
        sub = *(char**)(state + 0x40c);
        ((GrimbleControl*)sub)->unk34 = 0;
        ((GrimbleControl*)sub)->unk3C = lbl_803E2F20;
        for (i = 0; i < count; i++)
        {
            if ((*(int (**)(int, f32, f32, f32, f32*, f32*, f32*))(*(int*)(*(int*)(*ptr + 0x68)) + 0x30))(
                    *ptr, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, &dist,
                    &hitY, &unk) != 0 &&
                dist < ((GrimbleControl*)sub)->unk3C)
            {
                ((GrimbleControl*)sub)->unk34 = *ptr;
                ((GrimbleControl*)sub)->unk3C = dist;
                ((GrimbleControl*)sub)->unk40 = hitY;
            }
            ptr++;
        }
        if (*(void**)&((GrimbleControl*)sub)->unk34 != NULL)
        {
            ((GrimbleControl*)sub)->pathObj = ((GrimbleControl*)sub)->unk34;
            ((GrimbleControl*)sub)->unk48 = ((GrimbleControl*)sub)->unk40;
            (*(void (**)(int, char*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x20))(
                ((GrimbleControl*)sub)->pathObj, sub + 0xc);
            (*(void (**)(int, f32, f32*, f32*, f32*))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x24))(
                ((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->unk48, (f32*)(sub + 0x1c), (f32*)(sub + 0x20),
                (f32*)(sub + 0x24));
            ((GrimbleControl*)sub)->baseRotX =
                (*(int (**)(int))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x34))(
                    ((GrimbleControl*)sub)->pathObj);
            ((GrimbleControl*)sub)->unk4C = ((GrimbleControl*)sub)->unk48;
            ((GrimbleControl*)sub)->unk46 = 0;
            ((GrimbleControl*)sub)->unk4 = ((GrimbleControl*)sub)->unk20;
            ((GrimbleControl*)sub)->unk8 = ((GameObject*)obj)->anim.localPosY;
            ((GrimbleControl*)sub)->unk0 = ((GrimbleControl*)sub)->unk4 - ((GrimbleControl*)sub)->unk8;
            diff = ((GameObject*)obj)->anim.rotX - (u16)((GrimbleControl*)sub)->baseRotX;
            if (diff > 0x8000)
            {
                diff -= 0xffff;
            }
            if (diff < -0x8000)
            {
                diff += 0xffff;
            }
            facing = 0;
            if (diff <= 0x3ffc && diff >= -0x3ffc)
            {
                facing = 1;
            }
            ((GrimbleControl*)sub)->reversed = facing;
            ((GameObject*)obj)->anim.rotX = ((GrimbleControl*)sub)->baseRotX + (!((GrimbleControl*)sub)->reversed <<
                15);
            f = ((GrimbleControl*)sub)->unk48 -
                (f32)((((GrimbleControl*)sub)->reversed << 1) - 1) *
                ((f32)(int)
            randomGetRange(0xa, 0x3c) / lbl_803E2F24
            )
            ;
            ((GrimbleControl*)sub)->targetProgress = f;
            f = ((GrimbleControl*)sub)->targetProgress;
            if (f > lbl_803E2EBC)
            {
            }
            else
            {
                f = lbl_803E2EBC;
            }
            ((GrimbleControl*)sub)->targetProgress = f;
            f = ((GrimbleControl*)sub)->targetProgress;
            if (f < lbl_803E2F0C)
            {
            }
            else
            {
                f = lbl_803E2F0C;
            }
            ((GrimbleControl*)sub)->targetProgress = f;
        }
    }
}

void grimble_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    char* state = ((GameObject*)obj)->extra;
    char* sub = *(char**)&((GrimbleState*)state)->unk40C;

    if (visible == 0 || ((GameObject*)obj)->unkF4 != 0)
    {
        return;
    }
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5,
                                                                   lbl_803E2EBC);
    if (((GrimbleControl*)sub)->unk50 > lbl_803E2EB8)
    {
        (*gBoneParticleEffectInterface)->spawnEffect((void*)obj, 0x52a, NULL, 0x64, NULL);
    }
    if ((((GrimbleState*)state)->unk400 & 0x60) != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E2EBC, 3, ((GrimbleState*)state)->unk3E8, 0);
    }
    if ((((GrimbleState*)state)->unk400 & 0x100) != 0)
    {
        objParticleFn_80099d84(obj, lbl_803E2EBC, 4, ((GrimbleState*)state)->unk3E8, 0);
        ((GrimbleState*)state)->unk400 = ((GrimbleState*)state)->unk400 & ~0x100;
    }
}

void grimble_update(int obj)
{
    char* state;
    char* sub;
    int def;

    state = ((GameObject*)obj)->extra;
    sub = *(char**)&((GrimbleState*)state)->unk40C;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((*gMapEventInterface)->shouldNotSaveTime(((GrimblePlacement*)def)->unk14) != 0)
        {
            (*(void (**)(int, int, char*, int, int, int, int, f32))(*(int*)gBaddieControlInterface +
                0x58))(obj, def, state, 0xa, 6,
                       0x10e, 0x36, lbl_803E2F28);
            ((GroundBaddieState*)state)->baddie.substate = 1;
            ((GroundBaddieState*)state)->baddie.moveJustStartedB = 1;
            ((GameObject*)obj)->anim.alpha = 0;
        }
    }
    else
    {
        if (*(void**)&((GrimbleControl*)sub)->unk34 != NULL)
        {
            void* target;
            int r;

            (*(void (**)(int, char*, void*, void*, f32, f32))(*(int*)gPlayerInterface + 0x8))(
                obj, state, gGrimbleStateHandlersA, gGrimbleStateHandlersB, lbl_803E2EBC, lbl_803E2EBC);
            (*(void (**)(int, f32, int, int, int))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) +
                0x24))(((GrimbleControl*)sub)->pathObj, ((GrimbleControl*)sub)->unk48,
                       obj + 0xc, obj + 0x10, obj + 0x14);
            (*(void (**)(int, char*, char*, int, char*, int, int, int))(*(int*)gBaddieControlInterface +
                0x54))(
                obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, state + 0x405, 0, 0, 0);
            r = (*(int (**)(int, char*, char*, int, int*, int*, int, int))(*(int*)gBaddieControlInterface +
                0x50))(
                obj, state, state + 0x35c, ((GroundBaddieState*)state)->gameBitB, lbl_803200E0, lbl_80320158, 3, 0);
            if (r == 0xe)
            {
                ((GrimbleState*)state)->unk405 = 2;
                ((GroundBaddieState*)state)->baddie.targetObj = Obj_GetPlayerObject();
            }
            {
                ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
                if (((GroundBaddieState*)state)->baddie.targetObj != NULL || *(s8*)&((GroundBaddieState*)state)->baddie.
                    hitPoints == 0)
                {
                    hitState->flags |= 1;
                    if ((*(int (**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
                        obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 1) != 0)
                    {
                        *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
                    }
                }
                else
                {
                    hitState->flags &= ~1;
                    target = (*(void *(**)(int, char*, f32, int))(*(int*)gBaddieControlInterface + 0x48))(
                        obj, state, (f32)((GroundBaddieState*)state)->aggroRange, 0x8000);
                    if (target != NULL)
                    {
                        ((GroundBaddieState*)state)->baddie.targetObj = target;
                        ((GroundBaddieState*)state)->baddie.hasTarget = 0;
                    }
                }
            }
        }
        else
        {
            fn_801627F4(obj);
        }
    }
}

void grimble_init(int obj, int p2, int p3)
{
    char* state = ((GameObject*)obj)->extra;
    u8 flags = 2;

    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (**)(int, int, char*, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, p2, state, 0, 0, 0, flags, lbl_803E2F28);
    ((GameObject*)obj)->animEventCallback = (void*)grimble_animEventCallback;
    (*(void (**)(int, char*, int))(*(int*)gPlayerInterface + 0x14))(obj, state, 0);
    ((GroundBaddieState*)state)->baddie.substate = 0;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2EB8;
    *(int*)(*(int*)(state + 0x40c) + 0x34) = 0;
}

undefined4
#pragma scheduling on
#pragma peephole on
FUN_801620c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int spinSign;
    undefined4 result;
    int jointObj;
    double dist;
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];

    jointObj = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(jointObj + 0x48) - lbl_803E3B94), *(int*)(jointObj + 0x38), &p0x,
     &p0y, &p0z);
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(jointObj + 0x48)), *(int*)(jointObj + 0x38), &p1x,
     &p1y, p1z);
    p0x = p0x - p1x;
    p0y = p0y - p1y;
    p0z = p0z - p1z[0];
    dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
    p0x = (float)dist;
    spinSign = FUN_80017730();
    *(short*)(param_9 + 2) = (short)spinSign * ((short)((int)*(char*)(jointObj + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        result = 0;
    }
    else
    {
        result = 6;
    }
    return result;
}

undefined4
FUN_80162450(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float offset;
    uint rnd;
    int spinSign;
    undefined4 result;
    int jointObj;
    double dist;
    ushort queryC;
    u8 queryB[2];
    ushort queryA[2];
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint angleArg;
    undefined8 scratch;

    jointObj = *(int*)(*(int*)(param_9 + 0x5c) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 3, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 9);
    angleArg = *(char*)(jointObj + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)angleArg),
        *(int*)(jointObj + 0x38), jointObj + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(jointObj + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(jointObj + 0x48))
        {
            *(float*)(jointObj + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(jointObj + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(jointObj + 0x48) - lbl_803E3B94), *(int*)(jointObj + 0x38), &p0x,
     &p0y, &p0z);
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(jointObj + 0x48)), *(int*)(jointObj + 0x38), &p1x,
     &p1y, p1z);
    p0x = p0x - p1x;
    p0y = p0y - p1y;
    p0z = p0z - p1z[0];
    dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
    p0x = (float)dist;
    spinSign = FUN_80017730();
    angleArg = (int)(short)((short)spinSign * ((short)((int)*(char*)(jointObj + 0x45) << 1) + -1)) ^
        0x80000000;
    p1z[1] = 176.0;
    spinSign = (int)
    (-(lbl_803E3B98 * *(float*)(param_9 + 0x4c) - lbl_803E3B54) *
        (f32)(s32)
    angleArg
    )
    ;
    scratch = (double)(longlong)spinSign;
    param_9[1] = (short)spinSign;
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        result = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, queryA, queryB, &queryC);
        *(char*)(jointObj + 0x45) = '\x01' - *(char*)(jointObj + 0x45);
        rnd = countLeadingZeros((int)*(char*)(jointObj + 0x45));
        *param_9 = *(short*)(jointObj + 0x58) + (short)((rnd >> 5) << 0xf);
        rnd = randomGetRange(0x32, 100);
        offset = (float)((double)CONCAT44(0x43300000, *(char*)(jointObj + 0x45) * 2 - 1U ^ 0x80000000) -
            DOUBLE_803e3b70) * ((f32)(s32)(rnd) / lbl_803E3B9C);
        if ((queryA[0] < 4) || (0xb < queryA[0]))
        {
            rnd = (uint)queryC;
            if (rnd < 0x1f5)
            {
                scratch = (double)CONCAT44(0x43300000, rnd);
                offset = offset * (lbl_803E3B54 + (float)(scratch - DOUBLE_803e3ba8) / lbl_803E3BA0);
            }
            else
            {
                scratch = (double)CONCAT44(0x43300000, rnd);
                offset = offset * (lbl_803E3B54 + (float)(scratch - DOUBLE_803e3ba8) / lbl_803E3B9C);
            }
        }
        *(float*)(jointObj + 0x54) = *(float*)(jointObj + 0x48) - offset;
        offset = lbl_803E3B54;
        if (lbl_803E3B54 < *(float*)(jointObj + 0x54))
        {
            offset = *(float*)(jointObj + 0x54);
        }
        *(float*)(jointObj + 0x54) = offset;
        offset = lbl_803E3BA4;
        if (*(float*)(jointObj + 0x54) < lbl_803E3BA4)
        {
            offset = *(float*)(jointObj + 0x54);
        }
        *(float*)(jointObj + 0x54) = offset;
        result = 4;
    }
    return result;
}

undefined4
FUN_801628c4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool clamped;
    undefined4 result;
    int spinSign;
    int jointObj;
    double dist;
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint angleArg;

    jointObj = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 0);
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        FUN_80006824(param_9, SFXsc_death01);
    }
    angleArg = *(char*)(jointObj + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x28))
        ((double)(lbl_803E3BB0 *
             *(float*)(param_10 + 0x2a0) *
             (f32)(s32)angleArg),
        *(int*)(jointObj + 0x38), jointObj + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(jointObj + 0x48))
    {
        if (*(float*)(jointObj + 0x48) <= lbl_803E3B90)
        {
            clamped = false;
        }
        else
        {
            *(float*)(jointObj + 0x48) = lbl_803E3B90;
            clamped = true;
        }
    }
    else
    {
        *(float*)(jointObj + 0x48) = lbl_803E3B8C;
        clamped = true;
    }
    if (clamped)
    {
        result = 7;
    }
    else
    {
        (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
        ((double)(*(float*)(jointObj + 0x48) - lbl_803E3B94), *(int*)(jointObj + 0x38), &p0x,
         &p0y, &p0z);
        (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
        ((double)(lbl_803E3B94 + *(float*)(jointObj + 0x48)), *(int*)(jointObj + 0x38), &p1x,
         &p1y, p1z);
        p0x = p0x - p1x;
        p0y = p0y - p1y;
        p0z = p0z - p1z[0];
        dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
        p0x = (float)dist;
        spinSign = FUN_80017730();
        *(short*)(param_9 + 2) = (short)spinSign * ((short)((int)*(char*)(jointObj + 0x45) << 1) + -1);
        result = 0;
    }
    return result;
}

undefined4
FUN_80162b78(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 result;
    int spinSign;
    int jointObj;
    double dist;
    ushort queryC;
    u8 queryB[2];
    ushort queryA[2];
    float p0x;
    float p0y;
    float p0z;
    float p1x;
    float p1y;
    float p1z[2];
    uint angleArg;

    jointObj = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(u8*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    angleArg = *(char*)(jointObj + 0x45) * -2 + 1U ^ 0x80000000;
    p1z[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)angleArg),
        *(int*)(jointObj + 0x38), jointObj + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(jointObj + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(jointObj + 0x48))
        {
            *(float*)(jointObj + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(jointObj + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(*DAT_803dd738 + 0x14))
        (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, queryA, queryB, &queryC);
    if ((((queryA[0] < 4) || (0xb < queryA[0])) || (queryC < 0x191)) ||
        ((*(float*)(jointObj + 0x48) <= lbl_803E3B98 || (lbl_803E3BB4 <= *(float*)(jointObj + 0x48)))))
    {
        if (((int)*(char*)(jointObj + 0x45) ==
            ((uint)(byte)((*(float*)(jointObj + 0x54) <= *(float*)(jointObj + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char*)(param_10 + 0x346) == '\0'))
        {
            if ((*(uint*)(param_10 + 0x314) & 1) != 0)
            {
                *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
                FUN_80006824(param_9, SFXsc_death01);
            }
            (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
            ((double)(*(float*)(jointObj + 0x48) - lbl_803E3B94), *(int*)(jointObj + 0x38),
             &p0x, &p0y, &p0z);
            (**(code**)(**(int**)(*(int*)(jointObj + 0x38) + 0x68) + 0x24))
            ((double)(lbl_803E3B94 + *(float*)(jointObj + 0x48)), *(int*)(jointObj + 0x38),
             &p1x, &p1y, p1z);
            p0x = p0x - p1x;
            p0y = p0y - p1y;
            p0z = p0z - p1z[0];
            dist = FUN_80293900((double)(p0x * p0x + p0z * p0z));
            p0x = (float)dist;
            spinSign = FUN_80017730();
            *(short*)(param_9 + 2) = (short)spinSign * ((short)((int)*(char*)(jointObj + 0x45) << 1) + -1);
            result = 0;
        }
        else
        {
            result = 3;
        }
    }
    else
    {
        result = 3;
    }
    return result;
}

void grimble_release(void)
{
}

void cannonclaw_free(void);

int grimble_animEventCallback(void) { return 0x0; }
int grimble_getExtraSize(void) { return 0x46c; }
int grimble_getObjectTypeId(void) { return 0x59; }
int cannonclaw_getExtraSize(void);

#pragma dont_inline on
void grimble_initialiseStateHandlerTables(void);
#pragma dont_inline reset
void grimble_initialise(void) { grimble_initialiseStateHandlerTables(); }

#pragma scheduling off
#pragma peephole off
void grimble_free(int obj)
{
    int* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    (*(void (**)(int, int*, int))(*(int*)gBaddieControlInterface + 0x40))(obj, state, 0);
}

void grimble_hitDetect(int obj)
{
    (*(void (**)(int, int*, void*))(*(int*)gPlayerInterface + 0xC))(
        obj, ((GameObject*)obj)->extra, gGrimbleStateHandlersA);
}

void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

ObjectDescriptor gGrimbleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)grimble_initialise,
    (ObjectDescriptorCallback)grimble_release,
    0,
    (ObjectDescriptorCallback)grimble_init,
    (ObjectDescriptorCallback)grimble_update,
    (ObjectDescriptorCallback)grimble_hitDetect,
    (ObjectDescriptorCallback)grimble_render,
    (ObjectDescriptorCallback)grimble_free,
    (ObjectDescriptorCallback)grimble_getObjectTypeId,
    grimble_getExtraSize,
};

/* segment pragma-stack balance (re-split): */

/* Actual cannonclaw_update is 188b -- trigger-once cannon-arm awakener.
 * The 668b "Ghidra body" was misattributed; replaced with the right one. */

void tumbleweedbush_free(void);

void tumbleweedbush_hitDetect(void);

void tumbleweedbush_release(void);

void tumbleweedbush_initialise(void);

void tumbleweedbush_init(u8* obj, u8* params, int param3);

int tumbleweedbush_getExtraSize(void);
int tumbleweedbush_getObjectTypeId(void);

void tumbleweedbush_update(int* obj);

void tumbleweedbush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* tumbleweedbush_findNearestActive: scan all type-0x31 objects, pick the closest one whose
 * obj->_46 == 0x3fb and obj->_b8->_278 > 1 (by vec3f_distanceSquared from
 * the supplied position vector). Returns NULL if no match. */

/* tumbleweedbush_setScale: scan the sub-array at obj->_b8 (sub[0x50] entries
 * of 4 bytes each), zeroing every slot whose +0xc word matches `match`. */
void tumbleweedbush_setScale(u8* obj, void* match);

ObjectDescriptor11WithPadding gTumbleWeedBushObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)tumbleweedbush_initialise,
        (ObjectDescriptorCallback)tumbleweedbush_release,
        0,
        (ObjectDescriptorCallback)tumbleweedbush_init,
        (ObjectDescriptorCallback)tumbleweedbush_update,
        (ObjectDescriptorCallback)tumbleweedbush_hitDetect,
        (ObjectDescriptorCallback)tumbleweedbush_render,
        (ObjectDescriptorCallback)tumbleweedbush_free,
        (ObjectDescriptorCallback)tumbleweedbush_getObjectTypeId,
        tumbleweedbush_getExtraSize,
        (ObjectDescriptorCallback)tumbleweedbush_setScale,
    },
    0,
};
