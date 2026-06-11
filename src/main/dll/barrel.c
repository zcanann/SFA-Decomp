#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/dll/baddie_state.h"
#include "main/dll/grimble_state.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/barrel.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"
#include "main/objanim.h"
#include "main/objhits_types.h"

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
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008111c();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_803ad270;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd734;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3b70;
extern f64 DOUBLE_803e3ba8;
extern f32 lbl_803E3B50;
extern f32 lbl_803E3B54;
extern f32 lbl_803E3B7C;
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
extern f32 lbl_803E3BB8;
extern f32 lbl_803E3BBC;

/*
 * --INFO--
 *
 * Function: grimble_stateHandlerA02
 * EN v1.0 Address: 0x80161F0C
 * EN v1.0 Size: 436b
 * EN v1.1 Address: 0x80161FA4
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int getAngle(f32 dx, f32 dz);
extern double sqrtf(double x);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
extern void* Obj_GetPlayerObject(void);
extern void objParticleFn_80099d84(int obj, f32 a, int b, f32 c, int d);
extern void* gPlayerInterface;
extern void* gBaddieControlInterface;
extern MapEventInterface** gMapEventInterface;
extern int* lbl_803DCAB4;
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

#pragma scheduling off
#pragma peephole off
int grimble_stateHandlerA02(int obj, char* state, f32 arg)
{
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
    f32 z2, y2, x2, z, y, x;
    u8 hitEdge;
    s16 angle;
    double d;
    char* sub;

    sub = *(char**)(*(int*)&((GameObject*)obj)->extra + 0x40c);
    if (*(s8*)(state + 0x27a) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2EB8, 0);
        *(u8*)(state + 0x346) = 0;
    }
    (*(void (**)(int, char*, f32, int))(*(int*)gPlayerInterface + 0x20))(obj, state, arg, 0);
    if ((*(int*)(state + 0x314) & 1) != 0)
    {
        *(int*)(state + 0x314) = *(int*)(state + 0x314) & ~1;
        Sfx_PlayFromObject(obj, SFXsc_death01);
    }
    (*(void (**)(int, char*, f32))(*(int*)(*(int*)(((GrimbleControl*)sub)->pathObj + 0x68)) + 0x28))(
        ((GrimbleControl*)sub)->pathObj, sub + 0x48,
        lbl_803E2F18 * (*(f32*)(state + 0x2a0) * (f32)(1 - (((GrimbleControl*)sub)->reversed << 1))));
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
            if (diff < 0x3ffd && diff > -0x3ffd)
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
        (*(void (**)(int, int, int, int, int))(*(int*)lbl_803DCAB4 + 0xc))(obj, 0x52a, 0, 0x64,
                                                                           0);
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
        if ((*gMapEventInterface)->isTimedEventActive(((GrimblePlacement*)def)->unk14) != 0)
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

/*
 * --INFO--
 *
 * Function: FUN_801620c0
 * EN v1.0 Address: 0x801620C0
 * EN v1.0 Size: 460b
 * EN v1.1 Address: 0x801620F0
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
#pragma scheduling on
#pragma peephole on
FUN_801620c0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    undefined4 uVar2;
    int iVar3;
    double dVar4;
    float local_28;
    float local_24;
    float local_20;
    float local_1c;
    float local_18;
    float local_14[2];

    iVar3 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(iVar3 + 0x48) - lbl_803E3B94), *(int*)(iVar3 + 0x38), &local_28,
     &local_24, &local_20);
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(iVar3 + 0x48)), *(int*)(iVar3 + 0x38), &local_1c,
     &local_18, local_14);
    local_28 = local_28 - local_1c;
    local_24 = local_24 - local_18;
    local_20 = local_20 - local_14[0];
    dVar4 = FUN_80293900((double)(local_28 * local_28 + local_20 * local_20));
    local_28 = (float)dVar4;
    iVar1 = FUN_80017730();
    *(short*)(param_9 + 2) = (short)iVar1 * ((short)((int)*(char*)(iVar3 + 0x45) << 1) + -1);
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        uVar2 = 0;
    }
    else
    {
        uVar2 = 6;
    }
    return uVar2;
}


/*
 * --INFO--
 *
 * Function: FUN_80162450
 * EN v1.0 Address: 0x80162450
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x801623B8
 * EN v1.1 Size: 968b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162450(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, short* param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    uint uVar2;
    int iVar3;
    undefined4 uVar4;
    int iVar5;
    double dVar6;
    ushort local_58;
    undefined auStack_56[2];
    ushort local_54[2];
    float local_50;
    float local_4c;
    float local_48;
    float local_44;
    float local_40;
    float local_3c[2];
    uint uStack_34;
    undefined8 local_30;

    iVar5 = *(int*)(*(int*)(param_9 + 0x5c) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 3, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 9);
    uStack_34 = *(char*)(iVar5 + 0x45) * -2 + 1U ^ 0x80000000;
    local_3c[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)uStack_34),
        *(int*)(iVar5 + 0x38), iVar5 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar5 + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(iVar5 + 0x48))
        {
            *(float*)(iVar5 + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(iVar5 + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x24))
    ((double)(*(float*)(iVar5 + 0x48) - lbl_803E3B94), *(int*)(iVar5 + 0x38), &local_50,
     &local_4c, &local_48);
    (**(code**)(**(int**)(*(int*)(iVar5 + 0x38) + 0x68) + 0x24))
    ((double)(lbl_803E3B94 + *(float*)(iVar5 + 0x48)), *(int*)(iVar5 + 0x38), &local_44,
     &local_40, local_3c);
    local_50 = local_50 - local_44;
    local_4c = local_4c - local_40;
    local_48 = local_48 - local_3c[0];
    dVar6 = FUN_80293900((double)(local_50 * local_50 + local_48 * local_48));
    local_50 = (float)dVar6;
    iVar3 = FUN_80017730();
    uStack_34 = (int)(short)((short)iVar3 * ((short)((int)*(char*)(iVar5 + 0x45) << 1) + -1)) ^
        0x80000000;
    local_3c[1] = 176.0;
    iVar3 = (int)
    (-(lbl_803E3B98 * *(float*)(param_9 + 0x4c) - lbl_803E3B54) *
        (f32)(s32)
    uStack_34
    )
    ;
    local_30 = (double)(longlong)iVar3;
    param_9[1] = (short)iVar3;
    if (*(char*)(param_10 + 0x346) == '\0')
    {
        uVar4 = 0;
    }
    else
    {
        (**(code**)(*DAT_803dd738 + 0x14))
            (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, local_54, auStack_56, &local_58);
        *(char*)(iVar5 + 0x45) = '\x01' - *(char*)(iVar5 + 0x45);
        uVar2 = countLeadingZeros((int)*(char*)(iVar5 + 0x45));
        *param_9 = *(short*)(iVar5 + 0x58) + (short)((uVar2 >> 5) << 0xf);
        uVar2 = randomGetRange(0x32, 100);
        fVar1 = (float)((double)CONCAT44(0x43300000, *(char*)(iVar5 + 0x45) * 2 - 1U ^ 0x80000000) -
            DOUBLE_803e3b70) * ((f32)(s32)(uVar2) / lbl_803E3B9C);
        if ((local_54[0] < 4) || (0xb < local_54[0]))
        {
            uVar2 = (uint)local_58;
            if (uVar2 < 0x1f5)
            {
                local_30 = (double)CONCAT44(0x43300000, uVar2);
                fVar1 = fVar1 * (lbl_803E3B54 + (float)(local_30 - DOUBLE_803e3ba8) / lbl_803E3BA0);
            }
            else
            {
                local_30 = (double)CONCAT44(0x43300000, uVar2);
                fVar1 = fVar1 * (lbl_803E3B54 + (float)(local_30 - DOUBLE_803e3ba8) / lbl_803E3B9C);
            }
        }
        *(float*)(iVar5 + 0x54) = *(float*)(iVar5 + 0x48) - fVar1;
        fVar1 = lbl_803E3B54;
        if (lbl_803E3B54 < *(float*)(iVar5 + 0x54))
        {
            fVar1 = *(float*)(iVar5 + 0x54);
        }
        *(float*)(iVar5 + 0x54) = fVar1;
        fVar1 = lbl_803E3BA4;
        if (*(float*)(iVar5 + 0x54) < lbl_803E3BA4)
        {
            fVar1 = *(float*)(iVar5 + 0x54);
        }
        *(float*)(iVar5 + 0x54) = fVar1;
        uVar4 = 4;
    }
    return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_801628c4
 * EN v1.0 Address: 0x801628C4
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x80162780
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801628c4(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    bool bVar1;
    undefined4 uVar2;
    int iVar3;
    int iVar4;
    double dVar5;
    float local_48;
    float local_44;
    float local_40;
    float local_3c;
    float local_38;
    float local_34[2];
    uint uStack_2c;

    iVar4 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 0);
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        FUN_80006824(param_9, SFXsc_death01);
    }
    uStack_2c = *(char*)(iVar4 + 0x45) * -2 + 1U ^ 0x80000000;
    local_34[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x28))
        ((double)(lbl_803E3BB0 *
             *(float*)(param_10 + 0x2a0) *
             (f32)(s32)uStack_2c),
        *(int*)(iVar4 + 0x38), iVar4 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar4 + 0x48))
    {
        if (*(float*)(iVar4 + 0x48) <= lbl_803E3B90)
        {
            bVar1 = false;
        }
        else
        {
            *(float*)(iVar4 + 0x48) = lbl_803E3B90;
            bVar1 = true;
        }
    }
    else
    {
        *(float*)(iVar4 + 0x48) = lbl_803E3B8C;
        bVar1 = true;
    }
    if (bVar1)
    {
        uVar2 = 7;
    }
    else
    {
        (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
        ((double)(*(float*)(iVar4 + 0x48) - lbl_803E3B94), *(int*)(iVar4 + 0x38), &local_48,
         &local_44, &local_40);
        (**(code**)(**(int**)(*(int*)(iVar4 + 0x38) + 0x68) + 0x24))
        ((double)(lbl_803E3B94 + *(float*)(iVar4 + 0x48)), *(int*)(iVar4 + 0x38), &local_3c,
         &local_38, local_34);
        local_48 = local_48 - local_3c;
        local_44 = local_44 - local_38;
        local_40 = local_40 - local_34[0];
        dVar5 = FUN_80293900((double)(local_48 * local_48 + local_40 * local_40));
        local_48 = (float)dVar5;
        iVar3 = FUN_80017730();
        *(short*)(param_9 + 2) = (short)iVar3 * ((short)((int)*(char*)(iVar4 + 0x45) << 1) + -1);
        uVar2 = 0;
    }
    return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80162b78
 * EN v1.0 Address: 0x80162B78
 * EN v1.0 Size: 840b
 * EN v1.1 Address: 0x801629C4
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80162b78(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    undefined4 uVar1;
    int iVar2;
    int iVar3;
    double dVar4;
    ushort local_48;
    undefined auStack_46[2];
    ushort local_44[2];
    float local_40;
    float local_3c;
    float local_38;
    float local_34;
    float local_30;
    float local_2c[2];
    uint uStack_24;

    iVar3 = *(int*)(*(int*)(param_9 + 0xb8) + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E3B50, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(float*)(param_10 + 0x2a0) = lbl_803E3B88;
    (**(code**)(*DAT_803dd70c + 0x20))(param_1, param_9, param_10, 1);
    uStack_24 = *(char*)(iVar3 + 0x45) * -2 + 1U ^ 0x80000000;
    local_2c[1] = 176.0;
    (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x28))
        ((double)(*(float*)(param_10 + 0x280) *
             (f32)(s32)uStack_24),
        *(int*)(iVar3 + 0x38), iVar3 + 0x48
    )
    ;
    if (lbl_803E3B8C <= *(float*)(iVar3 + 0x48))
    {
        if (lbl_803E3B90 < *(float*)(iVar3 + 0x48))
        {
            *(float*)(iVar3 + 0x48) = lbl_803E3B90;
        }
    }
    else
    {
        *(float*)(iVar3 + 0x48) = lbl_803E3B8C;
    }
    (**(code**)(*DAT_803dd738 + 0x14))
        (param_9, *(undefined4*)(param_10 + 0x2d0), 0x10, local_44, auStack_46, &local_48);
    if ((((local_44[0] < 4) || (0xb < local_44[0])) || (local_48 < 0x191)) ||
        ((*(float*)(iVar3 + 0x48) <= lbl_803E3B98 || (lbl_803E3BB4 <= *(float*)(iVar3 + 0x48)))))
    {
        if (((int)*(char*)(iVar3 + 0x45) ==
            ((uint)(byte)((*(float*)(iVar3 + 0x54) <= *(float*)(iVar3 + 0x48)) << 1) << 0x1c) >> 0x1d
        ) || (*(char*)(param_10 + 0x346) == '\0'))
        {
            if ((*(uint*)(param_10 + 0x314) & 1) != 0)
            {
                *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
                FUN_80006824(param_9, SFXsc_death01);
            }
            (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(*(float*)(iVar3 + 0x48) - lbl_803E3B94), *(int*)(iVar3 + 0x38),
             &local_40, &local_3c, &local_38);
            (**(code**)(**(int**)(*(int*)(iVar3 + 0x38) + 0x68) + 0x24))
            ((double)(lbl_803E3B94 + *(float*)(iVar3 + 0x48)), *(int*)(iVar3 + 0x38),
             &local_34, &local_30, local_2c);
            local_40 = local_40 - local_34;
            local_3c = local_3c - local_30;
            local_38 = local_38 - local_2c[0];
            dVar4 = FUN_80293900((double)(local_40 * local_40 + local_38 * local_38));
            local_40 = (float)dVar4;
            iVar2 = FUN_80017730();
            *(short*)(param_9 + 2) = (short)iVar2 * ((short)((int)*(char*)(iVar3 + 0x45) << 1) + -1);
            uVar1 = 0;
        }
        else
        {
            uVar1 = 3;
        }
    }
    else
    {
        uVar1 = 3;
    }
    return uVar1;
}


/*
 * --INFO--
 *
 * Function: cannonclaw_release
 * EN v1.0 Address: 0x801631C0
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x80162F5C
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void cannonclaw_release(int arg1)
{
    undefined4 state;

    state = *(undefined4*)(arg1 + 0xb8);
    ObjGroup_RemoveObject(arg1, 3);
    (**(code**)(*DAT_803dd738 + 0x40))(arg1, state, 0);
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void grimble_release(void)
{
}

void cannonclaw_free(void)
{
}

void cannonclaw_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int grimble_animEventCallback(void) { return 0x0; }
int grimble_getExtraSize(void) { return 0x46c; }
int grimble_getObjectTypeId(void) { return 0x59; }
int cannonclaw_getExtraSize(void) { return 0x0; }
int cannonclaw_getObjectTypeId(void) { return 0x0; }

#pragma dont_inline on
#pragma scheduling off
void grimble_initialiseStateHandlerTables(void)
{
    gGrimbleStateHandlersA[0] = (void*)grimble_stateHandlerA00;
    gGrimbleStateHandlersA[1] = (void*)grimble_stateHandlerA01;
    gGrimbleStateHandlersA[2] = (void*)grimble_stateHandlerA02;
    gGrimbleStateHandlersA[3] = (void*)grimble_stateHandlerA03;
    gGrimbleStateHandlersA[4] = (void*)grimble_stateHandlerA04;
    gGrimbleStateHandlersA[5] = (void*)grimble_stateHandlerA05;
    gGrimbleStateHandlersA[6] = (void*)grimble_stateHandlerA06;
    gGrimbleStateHandlersA[7] = (void*)grimble_stateHandlerA07;
    gGrimbleStateHandlersA[8] = (void*)grimble_stateHandlerA08;
    gGrimbleStateHandlersA[9] = (void*)grimble_stateHandlerA09;
    gGrimbleStateHandlersB[0] = (void*)grimble_stateHandlerB00;
    gGrimbleStateHandlersB[1] = (void*)grimble_stateHandlerB01;
    gGrimbleStateHandlersB[2] = (void*)scarab_updateProximityGate;
    gGrimbleStateHandlersB[3] = (void*)grimble_stateHandlerB03;
    gGrimbleStateHandlersB[4] = (void*)grimble_stateHandlerB04;
    gGrimbleStateHandlersB[5] = (void*)grimble_stateHandlerB05;
}
#pragma dont_inline reset
void grimble_initialise(void) { grimble_initialiseStateHandlerTables(); }

extern f32 lbl_803E2F30;

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

void cannonclaw_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if (((GameObject*)obj)->unkF4 == 0)
        {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E2F30);
        }
    }
}

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
