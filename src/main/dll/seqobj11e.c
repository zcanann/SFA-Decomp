#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objtexture.h"

extern bool FUN_800067f8();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern int FUN_80039520();
extern undefined4 FUN_800810f0();
extern undefined4 FUN_80081108();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_8014d4c8();
extern byte FUN_8019e768();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();
extern int FUN_80294d20();
extern undefined4 FUN_80294d28();

extern undefined4 DAT_8031fee0;
extern undefined4 DAT_8031fee4;
extern undefined4 DAT_8031fee8;
extern undefined4 DAT_8031fee9;
extern undefined4 DAT_8031feea;
extern undefined4 DAT_8031feeb;
extern undefined4 DAT_803dc908;
extern undefined4 DAT_803dc910;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd71c;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DC918;
extern f32 lbl_803DC91C;
extern f32 lbl_803E34AC;
extern f32 lbl_803E34B8;
extern f32 lbl_803E34BC;
extern f32 lbl_803E34C0;
extern f32 lbl_803E34C4;
extern f32 lbl_803E34C8;
extern f32 lbl_803E34CC;
extern f32 lbl_803E34D0;
extern f32 lbl_803E34D4;
extern f32 lbl_803E34D8;
extern f32 lbl_803E34DC;
extern f32 lbl_803E34E0;
extern f32 lbl_803E34E4;
extern undefined2 uRam803dc90a;
extern undefined4 uRam803dc90c;

#pragma scheduling on
#pragma peephole on
void FUN_80152040(int obj, int state)
{
    int playerObj;
    int count;
    int def;

    playerObj = FUN_80017a98();
    def = *(int *)&((GameObject *)obj)->anim.placementData;
    count = (**(code**)(*DAT_803dd6e8 + 0x20))(0x1be);
    if (count == 0)
    {
        FUN_8011e800(2);
        *(undefined2*)(state + 0x338) = DAT_803dc908;
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
    }
    else if ((playerObj == 0) || (count = FUN_80294d20(playerObj), count < 0x19))
    {
        FUN_8011e800(2);
        *(undefined2*)(state + 0x338) = uRam803dc90a;
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
    }
    else
    {
        FUN_80294d28(playerObj, -0x19);
        GameBit_Set((int)*(short*)(def + 0x1c), 1);
        *(undefined2*)(state + 0x338) = uRam803dc90c;
        *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
        FUN_8011e800(2);
        (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void fn_80152440(GameObject* obj, int p, int p3, int msg)
{
    extern void fn_8014D08C(GameObject* obj, int p, int type, f32 t, int a, int b);
    extern f32 lbl_803E2810;
    extern f32 lbl_803E2814;
    int sub;
    f32 fz;

    sub = *(int*)&obj->anim.placementData;
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXen_cavedirt22);
    Sfx_PlayFromObject((u32)obj, SFXspirit_voice2);
    ((BaddieState*)p)->reactionFlags |= 0x8;
    *(f32*)(p + 0x32c) = (f32)(u32)(u16) * (s16*)(sub + 0x2c);
    fn_8014D08C(obj, p, 1, lbl_803E2810, 0, 0);
    *(u32*)&((BaddieState*)p)->unk2E4 &= ~0x20LL;
    fz = lbl_803E2814;
    obj->anim.velocityZ = lbl_803E2814;
    obj->anim.velocityY = fz;
    obj->anim.velocityX = fz;
}

/* EN v1.0 0x80152514  size: 1408b  main update: child-zap timer, curve
 * follow, heading steps, landing sfx, light-pulse fx, child spark spawn. */

extern int fn_80152370(int obj, int p2);
extern void Obj_FreeObject(int* obj);
extern int Curve_AdvanceAlongPath(RomCurveWalker* curve, f32 t);
extern u8 lbl_803DBCA8;
extern int fn_801A0174(int* obj);
extern int* Obj_GetPlayerObject(void);
extern void fn_8014CF7C(void* p1, void* p2, f32 f1, f32 f2, int p5, int p6);
extern void fn_8014D08C(void* p1, void* p2, int p3, f32 f1, int p5, int p6);
extern void objfx_spawnLightPulse(int* obj, f32 scale, int a, int b, int c, f32 v, void* params);
extern void objfx_spawnMaskedHitEffect(int* obj, f32 scale, int a, int b, int c, void* params);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern f32 lbl_803DBCB0;
extern f32 lbl_803DBCB4;
extern f32 lbl_803E2814;
extern f32 lbl_803E2820;
extern f32 lbl_803E2824;
extern f32 lbl_803E2828;
extern f32 lbl_803E282C;
extern f32 lbl_803E2830;
extern f32 lbl_803E2834;
extern f32 lbl_803E2838;
extern f32 lbl_803E283C;
extern f32 lbl_803E2840;
extern f32 lbl_803E2844;
extern f32 lbl_803E2848;
extern f32 lbl_803E284C;

typedef struct
{
    u8 pad[8];
    f32 a;
    f32 b;
    f32 c;
    f32 d;
} SeqFxParams;

void fn_80152514(int* obj, u8* state)
{
    int* def;
    RomCurveWalker* path;
    int attached;
    s16 spd;
    SeqFxParams fx;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    path = *(RomCurveWalker**)state;
    if (*(f32*)(state + 0x32c) > lbl_803E2814)
    {
        int* child = ((GameObject*)obj)->childObjs[0];
        if (child != 0)
        {
            Obj_FreeObject(child);
            ObjLink_DetachChild(obj, ((GameObject*)obj)->childObjs[0]);
            *(int*)&((GameObject*)obj)->childObjs[0] = 0;
        }
        *(f32*)(state + 0x32c) = *(f32*)(state + 0x32c) - timeDelta;
        if (*(f32*)(state + 0x32c) <= *(f32*)&lbl_803E2814)
        {
            *(f32*)(state + 0x32c) = lbl_803E2814;
            *(u32*)&((BaddieState*)state)->unk2E4 |= 0x20;
            Sfx_StopObjectChannel((u32)obj, 4);
            fn_8014D08C(obj, state, 0, lbl_803E2820, 0, 0);
        }
        else if (!(*(u32*)&((BaddieState*)state)->unk2E4 & 0x20))
        {
            return;
        }
    }
    if (((BaddieState*)state)->controlFlags & 0x2000)
    {
        int step;

        if (Curve_AdvanceAlongPath(path, ((BaddieState*)state)->pathStep) != 0 || path->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(path) != 0)
            {
                if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2824,
                                                     (int*)&lbl_803DBCA8, -1) != 0)
                {
                    ((BaddieState*)state)->controlFlags &= ~0x2000LL;
                }
            }
        }
        ((GameObject*)obj)->anim.velocityX = (path->posX - ((GameObject*)obj)->anim.localPosX) / timeDelta;
        ((GameObject*)obj)->anim.velocityZ = (path->posZ - ((GameObject*)obj)->anim.localPosZ) / timeDelta;
        step = (s8) * ((u8*)def + 0x2a);
        if (step == 0)
        {
            fn_8014CF7C(obj, state, path->posX, path->posZ, 0xf, 0);
        }
        else if (((BaddieState*)state)->controlFlags & 0x2000)
        {
            spd = step << 8;
            if ((int)(lbl_803E2828 * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            *(s16*)obj = *(s16*)obj - step;
            fn_8014CF7C(obj, state, path->posX, path->posZ, 0xf, 0);
            if ((int)(lbl_803E2828 * path->tangentY) >= 0)
            {
                step = spd;
            }
            else
            {
                step = -spd;
            }
            *(s16*)obj += step;
        }
        else
        {
            step = ((int)(lbl_803E2828 * path->tangentY) >= 0) ? step : -step;
            *(s16*)obj += step;
        }
        if (((GameObject*)obj)->anim.localPosY - path->posY < lbl_803E282C)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXar_laser216) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXar_laser216);
            }
            ((BaddieState*)state)->seqEntryIndex = 1;
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
    }
    else
    {
        if (((GameObject*)obj)->anim.localPosY - ((ObjPlacement*)def)->posY < lbl_803E2830)
        {
            if (Sfx_IsPlayingFromObject((u32)obj, SFXar_laser216) == 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXar_laser216);
            }
            ((BaddieState*)state)->seqEntryIndex = 1;
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
        *(s16*)obj += *(s8*)((char*)def + 0x2a);
    }
    if (((BaddieState*)state)->seqEntryIndex != 0)
    {
        ((GameObject*)obj)->anim.velocityY += lbl_803DBCB0 * timeDelta;
    }
    if (((GameObject*)obj)->objectFlags & 0x800)
    {
        f32 z = lbl_803E2814;
        fx.b = z;
        fx.c = z;
        fx.d = z;
        fx.a = lbl_803E2820;
        objfx_spawnLightPulse(obj, lbl_803E2834, 2, 0, 6, lbl_803E2838, &fx);
        fx.c = lbl_803E283C;
        objfx_spawnMaskedHitEffect(obj, lbl_803E2840, 1, 6, 0x20, &fx);
        fx.b = lbl_803E2814;
        z = lbl_803E2844;
        fx.c = z;
        fx.d = z;
    }
    if (((GameObject*)obj)->anim.velocityY < lbl_803E2848)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2848;
    }
    else if (((GameObject*)obj)->anim.velocityY > lbl_803E2834)
    {
        ((GameObject*)obj)->anim.velocityY = lbl_803E2834;
    }
    if (lbl_803E2814 == *(f32*)(state + 0x32c))
    {
        int* child2;

        if (*(s8*)((char*)def + 0x2e) != -1 &&
            (child2 = ((GameObject*)obj)->childObjs[0]) != 0 && fn_801A0174(child2) != 0)
        {
            ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), (int)obj, 0x16, 2, 0);
            fn_80152370((int)obj, 0x3b2);
            Sfx_PlayFromObject((u32)obj, SFXsp_literun116);
            *(f32*)(state + 0x32c) = lbl_803DBCB4;
        }
        if ((int)randomGetRange(0, (int)(lbl_803E284C * oneOverTimeDelta)) == 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXsp_literun114);
        }
        child2 = ((GameObject*)obj)->childObjs[0];
        if (child2 != 0)
        {
            ObjTextureRuntimeSlot* tex = objFindTexture(child2, 0, 0);
            int v;
            if (tex != 0)
            {
                v = tex->offsetS - 0x3c;
                if (v < 0)
                {
                    v += 0x2710;
                }
                tex->offsetS = v;
            }
        }
        else
        {
            int* newObj;
            int flag;

            if (*(s8*)((char*)def + 0x2a) != 0)
            {
                attached = 1;
            }
            else
            {
                attached = 0;
            }
            newObj = (int*)fn_80152370((int)obj, 0x639);
            flag = 0;
            if (*(s8*)((char*)def + 0x2a) != 0 && !(((BaddieState*)state)->controlFlags & 0x2000))
            {
                flag = 1;
            }
            *(int*)((char*)newObj + 0xf4) = flag;
            ObjLink_AttachChild(obj, newObj, attached);
        }
    }
}

/* EN v1.0 0x80152B90  size: 816b  firefly hover update: circle drift, bob
 * between heights, periodically drop a spawned object, ambient sfx timers. */

extern void fn_80293018(int idx, f32* outA, f32* outB);
extern u8 Obj_IsLoadingLocked(void);
extern u8* Obj_AllocObjectSetup(int size, int type);
extern int* loadObjectAtObject(int* obj, u8* setup);
extern void fn_8014CD1C(int* obj, u8* state, int p3, f32 a, f32 b, int p6);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E2868;
extern f32 lbl_803E286C;
extern f32 lbl_803E2878;
extern f32 lbl_803E287C;
extern f32 lbl_803E2880;
extern f32 lbl_803E2884;
extern f32 lbl_803E2888;
extern f32 lbl_803E288C;
extern f32 lbl_803E2890;
extern f32 lbl_803E2894;

void fn_80152B90(int* obj, u8* state)
{
    f32 y;
    f32 sinOut;
    f32 cosOut;

    *(u16*)(state + 0x338) = lbl_803E287C * timeDelta + (f32)(u32) * (u16*)(state + 0x338);
    fn_80293018(*(u16*)(state + 0x338), &sinOut, &cosOut);
    sinOut = sinOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    cosOut = cosOut * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        f32 dx;
        f32 dz;

        y = ((GameObject*)obj)->anim.localPosY;
        dx = *(f32*)(state + 0x324) - *(f32*)(*(int*)&((BaddieState*)state)->trackedObj + 0xc);
        dz = *(f32*)(state + 0x32c) - *(f32*)(*(int*)&((BaddieState*)state)->trackedObj + 0x14);
        if (sqrtf(dx * dx + dz * dz) <= lbl_803E2880 * ((BaddieState*)state)->unk2A8)
        {
            ((BaddieState*)state)->seqEntryIndex = 1;
            ((BaddieState*)state)->inWhirlpoolGroup = 0;
        }
    }
    else if (((BaddieState*)state)->seqEntryIndex == 1)
    {
        y = ((GameObject*)obj)->anim.localPosY - lbl_803E2884 * timeDelta;
        if (y <= *(f32*)(state + 0x328) - lbl_803E2888)
        {
            ((BaddieState*)state)->seqEntryIndex = 2;
        }
        else
        {
            ((BaddieState*)state)->inWhirlpoolGroup = (f32)(u32)((BaddieState*)state)->inWhirlpoolGroup + timeDelta;
            if (((BaddieState*)state)->inWhirlpoolGroup > 0x64)
            {
                ((BaddieState*)state)->inWhirlpoolGroup = 0;
                if (Obj_IsLoadingLocked() != 0)
                {
                    u8* setup;
                    int* spawned;

                    setup = Obj_AllocObjectSetup(0x24, 0x6b5);
                    ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
                    ((ObjPlacement*)setup)->posY = lbl_803E2878 + ((GameObject*)obj)->anim.localPosY;
                    ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
                    *(u8*)(setup + 4) = 1;
                    *(u8*)(setup + 5) = 1;
                    *(u8*)(setup + 6) = 0xff;
                    *(u8*)(setup + 7) = 0xff;
                    spawned = loadObjectAtObject(obj, setup);
                    if (spawned != 0)
                    {
                        *(int**)((char*)spawned + 0xc4) = obj;
                        Sfx_PlayFromObject((u32)obj, 0x249);
                    }
                }
            }
        }
    }
    else
    {
        y = lbl_803E288C * timeDelta + ((GameObject*)obj)->anim.localPosY;
        if (y >= *(f32*)(state + 0x328))
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
    }
    ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (sinOut - ((GameObject*)obj)->anim.localPosX);
    ((GameObject*)obj)->anim.velocityY = oneOverTimeDelta * (y - ((GameObject*)obj)->anim.localPosY);
    ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (cosOut - ((GameObject*)obj)->anim.localPosZ);
    fn_8014CD1C(obj, state, 0xf, lbl_803E2890, lbl_803E2894, 0);
    *(f32*)(state + 0x334) = *(f32*)(state + 0x334) - timeDelta;
    if (*(f32*)(state + 0x334) <= lbl_803E2868)
    {
        *(f32*)(state + 0x334) = (f32)(int)
        randomGetRange(0x3c, 0x78);
        Sfx_PlayFromObject((u32)obj, 0x31);
    }
    *(f32*)(state + 0x330) = *(f32*)(state + 0x330) - timeDelta;
    if (*(f32*)(state + 0x330) <= lbl_803E2868)
    {
        *(f32*)(state + 0x330) = lbl_803E286C;
        Sfx_PlayFromObject((u32)obj, 0x24a);
    }
}

int fn_80152370(int obj, int p2)
{
    extern void*Obj_GetPlayerObject(void);
    extern u8 Obj_IsLoadingLocked(void);
    extern u8*Obj_AllocObjectSetup(int size, int type);
    extern u8*Obj_SetupObject(u8* obj, int a, int b, int c, int d);
    int sub;
    u8* no;

    sub = *(int*)&((GameObject*)obj)->anim.placementData;
    Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() == 0) return 0;
    no = Obj_AllocObjectSetup(36, p2);
    *(s16*)(no + 0) = (s16)p2;
    *(u8*)(no + 4) = *(u8*)(sub + 4);
    *(u8*)(no + 6) = *(u8*)(sub + 6);
    *(u8*)(no + 5) = 1;
    *(u8*)(no + 7) = *(u8*)(sub + 7);
    *(f32*)(no + 8) = ((GameObject*)obj)->anim.localPosX;
    *(f32*)(no + 0xc) = ((GameObject*)obj)->anim.localPosY;
    *(f32*)(no + 0x10) = ((GameObject*)obj)->anim.localPosZ;
    *(u8*)(no + 0x19) = 0;
    *(s16*)(no + 0x20) = 149;
    return (int)Obj_SetupObject(no, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
}

#pragma scheduling on
#pragma peephole on
void FUN_801523f8(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint obj, int state)
{
    ushort nextMove;
    uint cur;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int rowOff;

    rowOff = *(int *)&((GameObject *)obj)->anim.placementData;
    if ((*(char*)(state + 0x33a) == '\x02') &&
        (cur = GameBit_Get((int)*(short*)(rowOff + 0x1c)), cur == 0))
    {
        *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode & 0xf7;
        if ((*(byte *)&((GameObject *)obj)->anim.resetHitboxMode & 4) != 0)
        {
            FUN_8011e868(7);
        }
        if ((*(byte *)&((GameObject *)obj)->anim.resetHitboxMode & 1) != 0)
        {
            FUN_80152040(obj, state);
        }
    }
    else
    {
        *(byte *)&((GameObject *)obj)->anim.resetHitboxMode = *(byte *)&((GameObject *)obj)->anim.resetHitboxMode | 8;
    }
    if (((*(uint*)(state + 0x2dc) & 0x80000000) != 0) &&
        (*(int*)(&DAT_8031fee4 + (uint) * (byte*)(state + 0x33a) * 0xc) != 0))
    {
        *(uint*)(state + 0x2dc) = *(uint*)(state + 0x2dc) | 0x40000000;
    }
    if ((*(uint*)(state + 0x2dc) & 0x40000000) != 0)
    {
        cur = (uint) * (byte*)(state + 0x33a);
        if (cur == 0)
        {
            if ((*(uint*)(state + 0x2dc) & 0x20000000) != 0)
            {
                cur = GameBit_Get((int)*(short*)(rowOff + 0x1c));
                if (cur == 0)
                {
                    *(u8*)(state + 0x33a) =
                        (&DAT_8031fee9)[(uint) * (byte*)(state + 0x33a) * 0xc];
                }
                else
                {
                    *(u8*)(state + 0x33a) =
                        (&DAT_8031feea)[(uint) * (byte*)(state + 0x33a) * 0xc];
                }
            }
        }
        else if (cur == 2)
        {
            cur = GameBit_Get((int)*(short*)(rowOff + 0x1c));
            if ((cur != 0) || ((*(uint*)(state + 0x2dc) & 0x20000000) == 0))
            {
                *(u8*)(state + 0x33a) = (&DAT_8031fee9)[(uint) * (byte*)(state + 0x33a) * 0xc];
            }
        }
        else if (cur == 3)
        {
            cur = GameBit_Get((int)*(short*)(rowOff + 0x1c));
            if (cur == 0)
            {
                *(u8*)(state + 0x33a) = (&DAT_8031fee9)[(uint) * (byte*)(state + 0x33a) * 0xc];
            }
            else
            {
                *(u8*)(state + 0x33a) = (&DAT_8031feea)[(uint) * (byte*)(state + 0x33a) * 0xc];
            }
        }
        else
        {
            *(u8*)(state + 0x33a) = (&DAT_8031fee9)[cur * 0xc];
        }
        nextMove = (ushort)(byte)(&DAT_8031fee8)[(uint) * (byte*)(state + 0x33a) * 0xc];
        if (*(ushort *)&((GameObject *)obj)->anim.currentMove != nextMove)
        {
            if ((nextMove != 0) && (nextMove != 4))
            {
                FUN_80006824(obj, 0x4a8);
            }
            rowOff = (uint) * (byte*)(state + 0x33a) * 0xc;
            FUN_8014d4c8((double)*(float*)(&DAT_8031fee0 + rowOff), param_2, param_3, param_4, param_5, param_6
                         , param_7, param_8, obj, state, (uint)(byte)(&DAT_8031fee8)[rowOff], 0, 0xf, in_r8,
                         in_r9, in_r10);
        }
    }
    if ((&DAT_8031feeb)[(uint) * (byte*)(state + 0x33a) * 0xc] != '\0')
    {
        FUN_80152194(obj, state);
    }
    return;
}

undefined4
FUN_80152a30(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int obj, undefined2 objType
)
{
    uint loadingLocked;
    undefined4 result;
    undefined2* setup;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    int def;

    def = *(int *)&((GameObject *)obj)->anim.placementData;
    FUN_80017a98();
    loadingLocked = FUN_80017ae8();
    if ((loadingLocked & 0xff) == 0)
    {
        result = 0;
    }
    else
    {
        setup = FUN_80017aa4(0x24, objType);
        *setup = objType;
        *(u8*)(setup + 2) = *(u8*)(def + 4);
        *(u8*)(setup + 3) = *(u8*)(def + 6);
        *(u8*)((int)setup + 5) = 1;
        *(u8*)((int)setup + 7) = *(u8*)(def + 7);
        *(undefined4*)(setup + 4) = *(undefined4*)(obj + 0xc);
        *(undefined4*)(setup + 6) = *(undefined4*)(obj + 0x10);
        *(undefined4*)(setup + 8) = *(undefined4*)(obj + 0x14);
        *(u8*)((int)setup + 0x19) = 0;
        setup[0x10] = 0x95;
        result = FUN_80017ae4(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8, setup, 5,
                             ((GameObject*)obj)->anim.mapEventSlot, 0xffffffff, *(uint**)&((GameObject *)obj)->anim.parent, in_r8,
                             in_r9, in_r10);
    }
    return result;
}

#pragma scheduling off
void fn_80152A94(int obj, int p)
{
    extern f32 lbl_803E2814;
    extern f32 lbl_803E2820;
    extern f32 lbl_803E2850;
    extern f32 lbl_803E2854;
    extern f32 lbl_803E2858;
    extern f32 lbl_803E285C;
    extern f32 lbl_803E2860;
    f32 fz;

    ((BaddieState*)p)->speedScale = lbl_803E2850;
    *(u32*)&((BaddieState*)p)->unk2E4 = 41;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x7000;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x20000LL;
    ((BaddieState*)p)->unk308 = lbl_803E2854;
    ((BaddieState*)p)->unk300 = lbl_803E2858;
    ((BaddieState*)p)->unk304 = lbl_803E285C;
    ((BaddieState*)p)->unk320 = 0;
    fz = lbl_803E2820;
    *(f32*)&((BaddieState*)p)->eventFlags = fz;
    ((BaddieState*)p)->unk321 = 0;
    ((BaddieState*)p)->unk318 = fz;
    ((BaddieState*)p)->unk322 = 0;
    ((BaddieState*)p)->unk31C = fz;
    *(f32*)(p + 0x32c) = lbl_803E2814;
    ((GameObject*)obj)->anim.hitboxScale = lbl_803E2860;
    Sfx_AddLoopedObjectSound((u32)obj, SFXsp_literun115);
}

void fn_80152B2C(int obj, int p, int param3, int msg)
{
    if (msg == 16 || msg == 17)
    {
        return;
    }
    Sfx_PlayFromObject((u32)obj, SFXfox_cough1);
    *(s16*)&((BaddieState*)p)->hitCounter = 0;
    *(u32*)&((BaddieState*)p)->unk2E4 |= 0x20;
    ((BaddieState*)p)->reactionFlags |= 0x8;
}

#pragma scheduling on
void FUN_80152cf0(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8)
{
    short* psVar1;
    int iVar2;
    char cVar7;
    short sVar5;
    short sVar6;
    bool bVar8;
    byte bVar9;
    uint uVar3;
    undefined4 uVar4;
    undefined4* puVar10;
    undefined4 in_r8;
    undefined4 in_r9;
    undefined4 in_r10;
    float* pfVar11;
    int iVar12;
    double dVar13;
    undefined8 uVar14;
    u8 auStack_48[8];
    float local_40;
    float local_3c;
    float local_38;
    float local_34;
    longlong local_30;
    longlong local_28;

    uVar14 = FUN_80286840();
    psVar1 = (short*)((ulonglong)uVar14 >> 0x20);
    puVar10 = (undefined4*)uVar14;
    iVar12 = *(int*)(psVar1 + 0x26);
    pfVar11 = (float*)*puVar10;
    if ((double)lbl_803E34AC < (double)(float)puVar10[0xcb])
    {
        if (*(int*)(psVar1 + 100) != 0)
        {
            FUN_80017ac8((double)(float)puVar10[0xcb], param_2, param_3, param_4, param_5, param_6, param_7,
                         param_8, *(int*)(psVar1 + 100));
            ObjLink_DetachChild((int)psVar1, *(int*)(psVar1 + 100));
            psVar1[100] = 0;
            psVar1[0x65] = 0;
        }
        puVar10[0xcb] = (float)puVar10[0xcb] - lbl_803DC074;
        if (lbl_803E34AC < (float)puVar10[0xcb])
        {
            if ((puVar10[0xb9] & 0x20) == 0) goto LAB_80152f28;
        }
        else
        {
            puVar10[0xcb] = lbl_803E34AC;
            puVar10[0xb9] = puVar10[0xb9] | 0x20;
            FUN_8000680c((int)psVar1, 4);
            FUN_8014d4c8((double)lbl_803E34B8, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         (int)psVar1, (int)puVar10, 0, 0, 0, in_r8, in_r9, in_r10);
        }
    }
    if ((puVar10[0xb7] & 0x2000) == 0)
    {
        if (lbl_803E34C8 <= *(float*)(psVar1 + 8) - *(float*)(iVar12 + 0xc))
        {
            *(u8*)((int)puVar10 + 0x33a) = 0;
        }
        else
        {
            bVar8 = FUN_800067f8((int)psVar1, 0x18d);
            if (!bVar8)
            {
                FUN_80006824((uint)psVar1, SFXar_laser216);
            }
            *(u8*)((int)puVar10 + 0x33a) = 1;
        }
        *psVar1 = *psVar1 + (short)*(char*)(iVar12 + 0x2a);
    }
    else
    {
        iVar2 = FUN_80006a10((double)(float)puVar10[0xbf], pfVar11);
        if ((((iVar2 != 0) || (pfVar11[4] != 0.0)) &&
                (cVar7 = (**(code**)(*DAT_803dd71c + 0x90))(pfVar11), cVar7 != '\0')) &&
            (cVar7 = (**(code**)(*DAT_803dd71c + 0x8c))
                ((double)lbl_803E34BC, *puVar10, psVar1, &DAT_803dc910, 0xffffffff),
                cVar7 != '\0'))
        {
            puVar10[0xb7] = puVar10[0xb7] & 0xffffdfff;
        }
        *(float*)(psVar1 + 0x12) = (pfVar11[0x1a] - *(float*)(psVar1 + 6)) / lbl_803DC074;
        *(float*)(psVar1 + 0x16) = (pfVar11[0x1c] - *(float*)(psVar1 + 10)) / lbl_803DC074;
        iVar2 = (int)*(char*)(iVar12 + 0x2a);
        if (iVar2 == 0)
        {
            param_2 = (double)pfVar11[0x1c];
            FUN_8014d3d0(psVar1, puVar10, 0xf, 0);
        }
        else if ((puVar10[0xb7] & 0x2000) == 0)
        {
            local_28 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
            if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0)
            {
                iVar2 = -iVar2;
            }
            *psVar1 = *psVar1 + (short)iVar2;
        }
        else
        {
            sVar6 = (short)(iVar2 << 8);
            local_30 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
            sVar5 = sVar6;
            if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0)
            {
                sVar5 = -sVar6;
            }
            *psVar1 = *psVar1 - sVar5;
            param_2 = (double)pfVar11[0x1c];
            FUN_8014d3d0(psVar1, puVar10, 0xf, 0);
            local_28 = (longlong)(int)(lbl_803E34C0 * pfVar11[0x1e]);
            if ((int)(lbl_803E34C0 * pfVar11[0x1e]) < 0)
            {
                sVar6 = -sVar6;
            }
            *psVar1 = *psVar1 + sVar6;
        }
        if (lbl_803E34C4 <= *(float*)(psVar1 + 8) - pfVar11[0x1b])
        {
            *(u8*)((int)puVar10 + 0x33a) = 0;
        }
        else
        {
            bVar8 = FUN_800067f8((int)psVar1, 0x18d);
            if (!bVar8)
            {
                FUN_80006824((uint)psVar1, SFXar_laser216);
            }
            *(u8*)((int)puVar10 + 0x33a) = 1;
        }
    }
    if (*(char*)((int)puVar10 + 0x33a) != '\0')
    {
        param_2 = (double)lbl_803DC918;
        *(float*)(psVar1 + 0x14) =
            (float)(param_2 * (double)lbl_803DC074 + (double)*(float*)(psVar1 + 0x14));
    }
    if ((psVar1[0x58] & 0x800U) != 0)
    {
        local_3c = lbl_803E34AC;
        local_38 = lbl_803E34AC;
        local_34 = lbl_803E34AC;
        local_40 = lbl_803E34B8;
        param_2 = (double)lbl_803E34D0;
        FUN_80081108((double)lbl_803E34CC, param_2);
        local_38 = lbl_803E34D4;
        FUN_800810f0((double)lbl_803E34D8, psVar1, 1, 6, 0x20, (int)auStack_48);
        local_3c = lbl_803E34AC;
        local_38 = lbl_803E34DC;
        local_34 = lbl_803E34DC;
    }
    if (lbl_803E34E0 <= *(float*)(psVar1 + 0x14))
    {
        if (lbl_803E34CC < *(float*)(psVar1 + 0x14))
        {
            *(float*)(psVar1 + 0x14) = lbl_803E34CC;
        }
    }
    else
    {
        *(float*)(psVar1 + 0x14) = lbl_803E34E0;
    }
    dVar13 = (double)lbl_803E34AC;
    if (dVar13 == (double)(float)puVar10[0xcb])
    {
        if (((*(char*)(iVar12 + 0x2e) != -1) && (*(int*)(psVar1 + 100) != 0)) &&
            (bVar9 = FUN_8019e768(*(int*)(psVar1 + 100)), bVar9 != 0))
        {
            iVar2 = FUN_80017a98();
            ObjHits_RecordObjectHit(iVar2, (int)psVar1, 0x16, 2, 0);
            FUN_80152a30(dVar13, param_2, param_3, param_4, param_5, param_6, param_7, param_8, (int)psVar1, 0x3b2);
            FUN_80006824((uint)psVar1, SFXsp_literun116);
            puVar10[0xcb] = lbl_803DC91C;
        }
        dVar13 = (double)lbl_803E34E4;
        local_28 = (longlong)(int)(dVar13 * (double)lbl_803DC078);
        uVar3 = randomGetRange(0, (int)(dVar13 * (double)lbl_803DC078));
        if (uVar3 == 0)
        {
            dVar13 = (double)FUN_80006824((uint)psVar1, SFXsp_literun114);
        }
        if (*(int*)(psVar1 + 100) == 0)
        {
            cVar7 = *(char*)(iVar12 + 0x2a);
            iVar2 = FUN_80152a30(dVar13, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                 (int)psVar1, 0x639);
            uVar4 = 0;
            if ((*(char*)(iVar12 + 0x2a) != '\0') && ((puVar10[0xb7] & 0x2000) == 0))
            {
                uVar4 = 1;
            }
            *(undefined4*)(iVar2 + 0xf4) = uVar4;
            ObjLink_AttachChild((int)psVar1, iVar2, (ushort)(cVar7 != '\0'));
        }
        else
        {
            iVar12 = FUN_80039520(*(int*)(psVar1 + 100), 0);
            if (iVar12 != 0)
            {
                iVar2 = *(short*)(iVar12 + 8) + -0x3c;
                if (iVar2 < 0)
                {
                    iVar2 = *(short*)(iVar12 + 8) + 0x26d4;
                }
                *(short*)(iVar12 + 8) = (short)iVar2;
            }
        }
    }
LAB_80152f28:
    FUN_8028688c();
    return;
}

extern f32 lbl_803E27F8;
extern f32 lbl_803E27FC;
extern f32 lbl_803E2800;
extern f32 lbl_803E2804;
extern f32 lbl_803E2808;
extern f32 lbl_803E280C;

#pragma scheduling off
#pragma peephole off
void fn_801522E0(int* obj, u8* state)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    ((BaddieState*)state)->speedScale = lbl_803E27F8;
    ((BaddieState*)state)->unk2A8 = lbl_803E27FC;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk2E4 |= 0xC80;
    ((BaddieState*)state)->unk308 = lbl_803E2800;
    ((BaddieState*)state)->unk300 = lbl_803E2804;
    ((BaddieState*)state)->unk304 = lbl_803E2808;
    ((BaddieState*)state)->unk320 = 0;
    fz = lbl_803E280C;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 0;
    ((BaddieState*)state)->unk318 = fz;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    if ((s8) * ((s8*)sub + 46) != -1)
    {
        *(int*)&((BaddieState*)state)->controlFlags |= 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
}

/* EN v1.0 0x80152040  size: 672b  state-table driver: walks the 12-byte
 * lbl_8031F290 state rows, advancing on GameBit + sequence flags and kicking
 * the matching anim. */

typedef struct
{
    f32 animSpeed; /* 0x0 */
    u32 unk4; /* 0x4 */
    u8 anim; /* 0x8 */
    u8 next; /* 0x9 */
    u8 alt; /* 0xa */
    u8 flagB; /* 0xb */
} Seq11ERow;

extern Seq11ERow lbl_8031F290[];
extern void fn_80151C68(int* obj, u8* state);
extern void fn_80151DB8(int* obj, u8* state);

void fn_80152040(int* obj, u8* state)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    u32 flags;

    if (((BaddieState*)state)->seqEntryIndex == 2 && GameBit_Get(*(s16*)((char*)def + 0x1c)) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~8);
        if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1)
        {
            fn_80151C68(obj, state);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & 0x80000000)
    {
        if (lbl_8031F290[((BaddieState*)state)->seqEntryIndex].unk4 != 0)
        {
            u32 triggered = 0x40000000;
            ((BaddieState*)state)->controlFlags = flags | triggered;
        }
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & 0x40000000)
    {
        int anim;
        u8* animTbl;

        if (((BaddieState*)state)->seqEntryIndex == 0)
        {
            if (flags & 0x20000000)
            {
                if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0)
                {
                    ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].alt;
                }
                else
                {
                    ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].next;
                }
            }
        }
        else if (((BaddieState*)state)->seqEntryIndex == 2)
        {
            if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0 ||
                !(((BaddieState*)state)->controlFlags & 0x20000000))
            {
                ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].next;
            }
        }
        else if (((BaddieState*)state)->seqEntryIndex == 3)
        {
            if (GameBit_Get(*(s16*)((char*)def + 0x1c)) != 0)
            {
                ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].alt;
            }
            else
            {
                ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].next;
            }
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = lbl_8031F290[((BaddieState*)state)->seqEntryIndex].next;
        }
        anim = ((GameObject*)obj)->anim.currentMove;
        animTbl = (u8*)lbl_8031F290 + 8;
        if (anim != animTbl[((BaddieState*)state)->seqEntryIndex * 12])
        {
            if (animTbl[((BaddieState*)state)->seqEntryIndex * 12] != 0 && animTbl[((BaddieState*)state)->seqEntryIndex
                * 12] != 4)
            {
                Sfx_PlayFromObject((u32)obj, 0x4a8);
            }
            fn_8014D08C(obj, state, animTbl[((BaddieState*)state)->seqEntryIndex * 12],
                        *(f32*)((u8*)lbl_8031F290 + ((BaddieState*)state)->seqEntryIndex * 12), 0, 0xf);
        }
    }
    if (lbl_8031F290[((BaddieState*)state)->seqEntryIndex].flagB != 0)
    {
        fn_80151DB8(obj, state);
    }
}
