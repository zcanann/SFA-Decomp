#include "main/dll/DIM/dimcannon_state.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/DIM/DIMlevcontrol.h"
#include "main/dll/player_status.h"
#include "main/objseq.h"
#include "main/resource.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int FUN_8003964c();
extern undefined4 FUN_8011e800();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801b2640();
extern undefined4 FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294d38();
extern undefined4 FUN_80294d40();

extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcb68;
extern undefined4 DAT_803dcb6a;
extern undefined4 DAT_803dcb6c;
extern undefined4* DAT_803dd6e8;
extern f64 DOUBLE_803e5578;
extern f32 lbl_803DC074;
extern f32 lbl_803DCB5C;
extern f32 lbl_803DCB60;
extern f32 lbl_803DCB64;
extern f32 lbl_803DCB70;

#pragma scheduling on
#pragma peephole on
extern void objRenderFn_8003b8f4(f32 x);
extern f32 lbl_803E48E8;
STATIC_ASSERT(sizeof(DimCannonState) == 0xb4);
extern void* lbl_803DDB50;
extern void ObjMsg_AllocQueue(int* obj, int n);
extern int fn_801B2550(int* obj, int p2, ObjAnimUpdateState* animUpdate);
extern f32 lbl_803E48B8;
extern void DIMwooddoor_updateFallingDebris(int* obj);
extern void DIMwooddoor_updateShardAim(int* obj, f32 a, f32 b, f32 c, f32 d);
extern void DIMwooddoor_spawnShard(int* obj, int p2);
extern f32 getXZDistance(f32 * a, f32 * b);
extern void* fn_802972A8(void* player);
extern void buttonDisable(int chan, int mask);
extern u8 framesThisStep;
extern f32 timeDelta;
extern int lbl_803DBF10;
extern int lbl_803DBF0C;
extern f32 lbl_803E48EC;
extern f32 lbl_803E48F0;
extern f32 lbl_803DBEF4;
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern void hudFn_8011f38c(int v);
extern s16* objModelGetVecFn_800395d8(int* obj, int p2);
extern s8 padGetStickX(int chan);
extern void playerAddRemoveMagic(void* player, int amount);
extern u32 getButtonsJustPressed(int chan);
extern u32 getButtonsHeld(int chan);
extern u32 getButtonsJustPressedIfNotBusy(int chan);
extern u8 lbl_803DBF00;
extern s16 lbl_803DBF02;
extern s16 lbl_803DBF04;
extern f32 lbl_803DBF08;
extern f32 lbl_803DBEF8;
extern f32 lbl_803DBEFC;
extern void objRenderFn_8003b8f4(f32);

void FUN_801b2550(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  undefined4 param_9, undefined4 param_10, ObjAnimUpdateState* animUpdate)
{
    short sVar1;
    short sVar3;
    int iVar2;
    short* psVar4;
    int iVar5;
    uint uVar6;
    char cVar7;
    bool bVar8;
    bool bVar9;
    int iVar10;
    int iVar11;
    int iVar12;
    int iVar13;
    double dVar14;
    double dVar15;
    short* local_38[2];
    undefined4 local_30;
    uint uStack_2c;
    undefined8 local_28;

    psVar4 = (short*)FUN_80286838();
    iVar13 = *(int*)(psVar4 + 0x26);
    bVar9 = false;
    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair &= ~0x608;
    iVar12 = *(int*)(psVar4 + 0x5c);
    if (*(char*)(iVar12 + 0xac) == '\x03')
    {
        iVar13 = FUN_80017a98();
        FUN_8011e868(0x16);
        FUN_8011e844(0x17);
        FUN_8011e800(1);
        iVar5 = (*gCameraInterface)->getMode();
        if ((iVar5 != 0x51) && (iVar5 != 0x4c))
        {
            local_38[0] = psVar4;
            (*gCameraInterface)->setMode(0x51, 1, 0, 4, local_38, 0x32, 0xff);
        }
        if (iVar5 == 0x51)
        {
            iVar5 = FUN_8003964c((int)psVar4, 0);
            if (*(char*)(iVar12 + 0xb0) < '\x01')
            {
                uVar6 = GameBit_Get(0xdb);
                if (uVar6 == 0)
                {
                    (**(code**)(*DAT_803dd6e8 + 0x38))(0x4b9, 0x14, 0x8c, 1);
                    GameBit_Set(0xdb, 1);
                }
                cVar7 = FUN_80006bd0(0);
                uStack_2c = (int)cVar7 ^ 0x80000000;
                local_30 = 0x43300000;
                iVar11 = (int)
                (-lbl_803DCB70 *
                    (f32)(s32)
                uStack_2c
                )
                ;
                local_28 = (double)(longlong)iVar11;
                if (iVar11 == 0)
                {
                    if (*(int*)(iVar12 + 0xa8) != 0)
                    {
                        FUN_80006824((uint)psVar4, SFXfoot_dinostep);
                    }
                }
                else
                {
                    sVar1 = *(short*)(iVar5 + 2);
                    sVar3 = sVar1;
                    if (sVar1 < 0)
                    {
                        sVar3 = -sVar1;
                    }
                    if ((int)DAT_803dcb6a - (int)DAT_803dcb6c < (int)sVar3)
                    {
                        if (iVar11 < 0)
                        {
                            iVar10 = -1;
                        }
                        else if (iVar11 < 1)
                        {
                            iVar10 = 0;
                        }
                        else
                        {
                            iVar10 = 1;
                        }
                        if (sVar1 < 0)
                        {
                            iVar2 = -1;
                        }
                        else if (sVar1 < 1)
                        {
                            iVar2 = 0;
                        }
                        else
                        {
                            iVar2 = 1;
                        }
                        if (iVar2 == iVar10)
                        {
                            iVar11 = (iVar11 * ((int)DAT_803dcb6a - (int)sVar3)) / (int)DAT_803dcb6c;
                        }
                    }
                    *(short*)(iVar5 + 2) = *(short*)(iVar5 + 2) + (short)iVar11;
                    FUN_800068c4((uint)psVar4, 0x1ff);
                }
                *(int*)(iVar12 + 0xa8) = iVar11;
                if (0 < *(short*)(iVar12 + 0xa4))
                {
                    *(ushort*)(iVar12 + 0xa4) = *(short*)(iVar12 + 0xa4) - (ushort)DAT_803dc070;
                }
                if (0 < *(short*)(iVar12 + 0xa6))
                {
                    *(ushort*)(iVar12 + 0xa6) = *(short*)(iVar12 + 0xa6) - (ushort)DAT_803dc070;
                }
                uVar6 = FUN_80006c10(0);
                if (((uVar6 & 0x100) == 0) || (0 < *(short*)(iVar12 + 0xa4)))
                {
                    FUN_8000680c((int)psVar4, 2);
                }
                else
                {
                    FUN_80006ba8(0, 0x100);
                    iVar5 = FUN_80294d38(iVar13);
                    if (iVar5 < 1)
                    {
                        FUN_80006824((uint)psVar4, 0x40c);
                    }
                    else
                    {
                        *(byte*)(iVar12 + 0xae) = *(char*)(iVar12 + 0xae) + DAT_803dc070;
                        bVar8 = FUN_800067f0((int)psVar4, 2);
                        if (!bVar8)
                        {
                            FUN_80006824((uint)psVar4, SFXfoot_water_roll);
                            FUN_80006824((uint)psVar4, SFXthorntail_annoyed1);
                        }
                    }
                }
                if (DAT_803dcb68 < *(byte*)(iVar12 + 0xae))
                {
                    *(byte*)(iVar12 + 0xae) = DAT_803dcb68;
                }
                (**(code**)(*DAT_803dd6e8 + 0x5c))(*(undefined*)(iVar12 + 0xae));
                local_28 = (double)CONCAT44(0x43300000, (uint) * (byte*)(iVar12 + 0xae));
                dVar15 = (double)(float)(local_28 - DOUBLE_803e5578);
                dVar14 = (double)lbl_803DCB64;
                *(float*)(iVar12 + 0x98) = (float)(dVar15 * dVar14 + (double)lbl_803DCB60);
                uVar6 = FUN_80006bf8(0);
                if (((((uVar6 & 0x100) != 0) || (*(byte*)(iVar12 + 0xae) == DAT_803dcb68)) &&
                    (*(short*)(iVar12 + 0xa4) < 1)) && (iVar5 = FUN_80294d38(iVar13), 0 < iVar5))
                {
                    FUN_80006ba8(0, 0x100);
                    dVar14 = (double)FUN_80294d40(iVar13, -1);
                    *(undefined*)(iVar12 + 0xad) = 1;
                    *(undefined*)(iVar12 + 0xae) = 0;
                }
                FUN_801b2640(dVar14, dVar15, param_3, param_4, param_5, param_6, param_7, param_8);
                if (((*(char*)(psVar4 + 0x56) == '\x13') && (*(char*)(iVar12 + 0xb2) == '\0')) &&
                    ((uVar6 = GameBit_Get(0xc17), uVar6 != 0 && (uVar6 = GameBit_Get(0xa21), uVar6 != 0))))
                {
                    *(undefined*)(iVar12 + 0xb2) = 1;
                    *(undefined*)(iVar12 + 0xb1) = 1;
                }
                if ((*(char*)(iVar12 + 0xb1) != '\0') &&
                    (*(byte*)(iVar12 + 0xb1) = *(char*)(iVar12 + 0xb1) + DAT_803dc070,
                        0x3c < *(byte*)(iVar12 + 0xb1)))
                {
                    bVar9 = true;
                }
                if ((bVar9) || (uVar6 = FUN_80006c00(0), (uVar6 & 0x200) != 0))
                {
                    FUN_80006ba8(0, 0x200);
                    FUN_8011e800(0);
                    (**(code**)(*DAT_803dd6e8 + 0x60))();
                    (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
                    *(undefined*)(iVar12 + 0xac) = 5;
                    *(undefined*)(iVar12 + 0xb0) = 0x3c;
                    animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
                    *(byte*)((int)psVar4 + 0xaf) = *(byte*)((int)psVar4 + 0xaf) & 0xf7;
                    bVar9 = FUN_800067f0((int)psVar4, 8);
                    if (bVar9)
                    {
                        FUN_800067f0((int)psVar4, 0);
                    }
                    FUN_8000680c((int)psVar4, 2);
                }
                FUN_8002fc3c((double)lbl_803DCB5C, (double)lbl_803DC074);
            }
            else
            {
                *(byte*)(iVar12 + 0xb0) = *(char*)(iVar12 + 0xb0) - DAT_803dc070;
                if (*(char*)(iVar12 + 0xb0) < '\x01')
                {
                    (**(code**)(*DAT_803dd6e8 + 0x58))(DAT_803dcb68, 0x5d5);
                }
            }
        }
    }
    else
    {
        psVar4[3] = psVar4[3] & 0xbfff;
        iVar5 = FUN_8003964c((int)psVar4, 0);
        *(short*)(iVar5 + 2) = *psVar4 - (short)((int)*(char*)(iVar13 + 0x28) << 8);
        *psVar4 = (short)((int)*(char*)(iVar13 + 0x28) << 8);
        *(undefined*)(iVar12 + 0xac) = 4;
    }
    FUN_80286884();
    return;
}

#pragma scheduling off
#pragma peephole off
void dimcannon_hitDetect(void)
{
}

void dimcannon_release(void)
{
}

void dimcannon_initialise(void)
{
}

void dimcannon_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* def;
    u8* sub;
    s16 saved;

    def = *(u8**)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->anim.seqId != 0x1d6)
    {
        sub = ((GameObject*)obj)->extra;
        saved = *(s16*)obj;
        *(s16*)obj = (s16)((s8)def[0x28] << 8);
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E48E8);
        *(s16*)obj = saved;
        ObjPath_GetPointWorldPosition((int)obj, 0, (f32*)(sub + 0x8c), (f32*)(sub + 0x90), (f32*)(sub + 0x94), 0);
    }
    else
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E48E8);
    }
}

void dimlavasmash_free(void);

/* 8b "li r3, N; blr" returners. */

/* if (o->_X == K) return A; else return B; */

typedef struct DimcannonPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x26 - 0x20];
    s16 unk26;
    s8 unk28;
    u8 pad29[0x30 - 0x29];
} DimcannonPlacement;

typedef struct DimcannonState
{
    u8 pad0[0x7 - 0x0];
    u8 unk7;
    u8 pad8[0x9 - 0x8];
    s8 unk9;
    s8 unkA;
    s8 unkB;
    u8 padC[0x10 - 0xC];
} DimcannonState;

/* dimcannon extra block (0xb4); the head is the per-cannonball column
 * arrays walked via state + i*4 (kept raw), this names the scalar tail. */

int dimcannon_getExtraSize(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1d6) return 0xc;
    return 0xb4;
}

int dimcannon_getObjectTypeId(int* obj)
{
    if (((GameObject*)obj)->anim.seqId == 0x1d6) return 0x0;
    return 0x0;
}

#pragma dont_inline on
#pragma dont_inline reset

void dimcannon_free(int* obj)
{
    if (((GameObject*)obj)->anim.seqId != 0x1d6)
    {
        ((void (*)(void))((int**)*gGameUIInterface)[0x18])();
        Resource_Release(lbl_803DDB50);
        lbl_803DDB50 = NULL;
    }
    ObjGroup_RemoveObject(obj, 3);
}

/* EN v1.0 0x801B30C8  size: 628b  Dimcannon constructor: handles the 0x1d6
 * sub-variant, else seeds the 10-slot trail particle array, installs the
 * sequence fn, acquires its model resource and applies map flags. */
void dimcannon_init(int* obj, int* arg)
{
    ObjMsg_AllocQueue(obj, 4);

    if (((GameObject*)obj)->anim.seqId == 0x1d6)
    {
        void* state;
        int* p;
        ((GameObject*)obj)->unkF4 = 0;
        p = *(int**)&((GameObject*)obj)->anim.modelState;
        if (p != 0)
        {
            *(int*)&((ObjHitsPriorityState*)p)->secondaryRadiusY |= 0xc10;
            p = *(int**)&((GameObject*)obj)->anim.modelState;
            *(u32*)&((ObjHitsPriorityState*)p)->secondaryRadiusY |= 0x8000LL;
        }
        state = ((GameObject*)obj)->extra;
        ((DimcannonState*)state)->unk9 = (s8)randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unkA = (s8)randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unkB = (s8)randomGetRange(-0x64, 0x64);
        ((DimcannonState*)state)->unk7 = 1;
        p = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (p != 0)
        {
            *(s16*)&((ObjHitsPriorityState*)p)->trackContactMask = 1;
        }
        ((GameObject*)obj)->objectFlags |= 0x4000;
    }
    else
    {
        void* state = ((GameObject*)obj)->extra;
        u8 i;

        if (((GameObject*)obj)->anim.mapEventSlot == 0x13)
        {
            int v = 0;
            if (GameBit_Get(0xc17) && GameBit_Get(0xa21))
            {
                v = 1;
            }
            ((DimCannonState*)state)->unkB2 = v;
        }

        for (i = 0; i < 0xa; i += 5)
        {
            *(f32*)((char*)state + i * 4 + 0x14) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x3c) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x64) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x18) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x40) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x68) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x1c) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x44) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x6c) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x20) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x48) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x70) = ((GameObject*)obj)->anim.localPosZ;
            *(f32*)((char*)state + i * 4 + 0x24) = ((GameObject*)obj)->anim.localPosX;
            *(f32*)((char*)state + i * 4 + 0x4c) = ((GameObject*)obj)->anim.localPosY;
            *(f32*)((char*)state + i * 4 + 0x74) = ((GameObject*)obj)->anim.localPosZ;
        }

        ((DimCannonState*)state)->unkAF = 0x80;
        ((DimCannonState*)state)->unk98 = lbl_803E48B8;
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
        ((GameObject*)obj)->animEventCallback = (void*)fn_801B2550;
        ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)arg + 0x28) << 8);
        lbl_803DDB50 = Resource_Acquire(0x79, 1);
        if (GameBit_Get(*(s16*)((char*)arg + 0x1a)))
        {
            *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
            ((DimCannonState*)state)->fireState = 5;
        }
        ((DimCannonState*)state)->unk8C = ((GameObject*)obj)->anim.localPosX;
        ((DimCannonState*)state)->unk90 = ((GameObject*)obj)->anim.localPosY;
        ((DimCannonState*)state)->unk94 = ((GameObject*)obj)->anim.localPosZ;
    }

    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* EN v1.0 0x801B2C68  size: 1120b  Dimcannon per-frame state machine: idle ->
 * tracking -> firing -> spent, plus the 0x1d6 falling-debris sub-variant. */
void dimcannon_update(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
    char* state;
    void* player;
    int* src = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((GameObject*)obj)->anim.seqId == 0x1d6)
    {
        DIMwooddoor_updateFallingDebris(obj);
        return;
    }

    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x8) && GameBit_Get(((DimcannonPlacement*)src)->unk1A))
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
    }

    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    if (fn_802972A8(player) != 0)
    {
        *(int*)(state + 0x0) = 0;
    }
    else
    {
        *(void**)(state + 0x0) = player;
    }

    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);

    switch (((DimCannonState*)state)->fireState)
    {
    case 0:
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1C))
        {
            ((DimCannonState*)state)->fireState = 4;
        }
        break;
    case 5:
        {
            s8 t = ((DimCannonState*)state)->unkB0;
            if (t > 0)
            {
                ((DimCannonState*)state)->unkB0 = (s8)(t - framesThisStep);
            }
            else if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 0x1)
            {
                int* focusObj;
                ((DimCannonState*)state)->unkAE = 0;
                ((DimCannonState*)state)->unkB1 = 0;
                focusObj = obj;
                (*gCameraInterface)->setMode(0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
                buttonDisable(0, 0x100);
                ((DimCannonState*)state)->fireState = 3;
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x8;
            }
            ((DimCannonState*)state)->unkAD = 0;
            ((DimCannonState*)state)->aimYaw = 0;
            ((DimCannonState*)state)->aimPitch = 0;
            break;
        }
    case 4:
        DIMwooddoor_updateShardAim(obj, *(f32*)&((DimCannonState*)state)->unk4, *(f32*)&((DimCannonState*)state)->unk8,
                                   ((DimCannonState*)state)->unkC, ((DimCannonState*)state)->unk10);
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1A))
        {
            ((DimCannonState*)state)->fireState = 5;
        }
        else if (*(void**)(state + 0x0) != 0 && !GameBit_Get(((DimcannonPlacement*)src)->unk1E))
        {
            f32 d = getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                  (f32*)(*(char**)(state + 0x0) + 0x18));
            int v = ((DimcannonPlacement*)src)->unk26 * lbl_803DBF10;
            if (d < (f32)v / lbl_803E48EC)
            {
                ((DimCannonState*)state)->fireState = 1;
            }
        }
        ((DimCannonState*)state)->unkAD = 0;
        ((DimCannonState*)state)->aimYaw = 0;
        ((DimCannonState*)state)->aimPitch = 0;
        break;
    case 1:
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1A))
        {
            ((DimCannonState*)state)->fireState = 5;
            break;
        }
        if (GameBit_Get(((DimcannonPlacement*)src)->unk1E))
        {
            ((DimCannonState*)state)->fireState = 4;
            break;
        }
        if (*(void**)(state + 0x0) != 0)
        {
            ((DimCannonState*)state)->unkAF += framesThisStep;
            if (((DimCannonState*)state)->unkAF > 0xa)
            {
                char* e;
                u8 j;
                ((DimCannonState*)state)->unkAF = 0;
                for (j = 0; j < 9; j++)
                {
                    e = state + j * 4;
                    *(f32*)(e + 0x14) = *(f32*)(e + 0x18);
                    *(f32*)(e + 0x3c) = *(f32*)(e + 0x40);
                    *(f32*)(e + 0x64) = *(f32*)(e + 0x68);
                    if (j == 0 || *(f32*)(e + 0x3c) > *(f32*)&((DimCannonState*)state)->unk8)
                    {
                        *(f32*)&((DimCannonState*)state)->unk8 = *(f32*)(e + 0x3c);
                    }
                }
                *(f32*)(state + 0x38) = *(f32*)(*(char**)(state + 0x0) + 0xc);
                *(f32*)(state + 0x60) = *(f32*)(*(char**)(state + 0x0) + 0x10);
                ((DimCannonState*)state)->unk88 = *(f32*)(*(char**)(state + 0x0) + 0x14);
                *(f32*)&((DimCannonState*)state)->unk4 = *(f32*)(state + 0x14);
                ((DimCannonState*)state)->unkC = *(f32*)(state + 0x64);
            }
            if (((DimCannonState*)state)->aimYaw > 0)
            {
                ((DimCannonState*)state)->aimYaw -= framesThisStep;
            }
            if (((DimCannonState*)state)->aimPitch > 0)
            {
                ((DimCannonState*)state)->aimPitch -= framesThisStep;
            }
            ((DimCannonState*)state)->unk10 = getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                                            (f32*)(*(char**)(state + 0x0) + 0x18));
            DIMwooddoor_updateShardAim(obj, *(f32*)&((DimCannonState*)state)->unk4,
                                       *(f32*)&((DimCannonState*)state)->unk8,
                                       ((DimCannonState*)state)->unkC, ((DimCannonState*)state)->unk10);
            DIMwooddoor_spawnShard(obj, 0);
            {
                f32 d2 = ((DimCannonState*)state)->unk10;
                int v = ((DimcannonPlacement*)src)->unk26 * lbl_803DBF0C;
                if (d2 > (f32)v / lbl_803E48EC)
                {
                    ((DimCannonState*)state)->fireState = 4;
                }
            }
        }
        else
        {
            ((DimCannonState*)state)->fireState = 4;
        }
        break;
    }

    lbl_803DBEF4 = lbl_803E48F0;
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E48F0, timeDelta, NULL);
}

/* EN v1.0 0x801B2550  size: 1504b  Dimcannon manned-control sequence: aims the
 * turret with the stick, charges with A, fires on release/full charge, and
 * exits on B or after the post-completion delay. */
int fn_801B2550(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern void* Obj_GetPlayerObject(void);
    char* state;
    int* src = *(int**)&((GameObject*)obj)->anim.placementData;
    int delta;
    u8 done = 0;
    int camMode;

    animUpdate->sequenceEventActive = 0;
    animUpdate->hitVolumePair &= ~0x608;
    state = ((GameObject*)obj)->extra;

    if (((DimCannonState*)state)->fireState == 0x3)
    {
        s16* vec;
        s8 timer;
        void* player;

        player = Obj_GetPlayerObject();
        setAButtonIcon(0x16);
        setBButtonIcon(0x17);
        hudFn_8011f38c(1);
        camMode = (*gCameraInterface)->getMode();
        if (camMode != 0x51 && camMode != 0x4c)
        {
            int* focusObj = obj;
            (*gCameraInterface)->setMode(0x51, 1, 0, 4, &focusObj, 0x32, 0xff);
        }
        if (camMode != 0x51)
        {
            return 0;
        }
        vec = objModelGetVecFn_800395d8(obj, 0);
        timer = ((DimCannonState*)state)->unkB0;
        if (timer > 0)
        {
            ((DimCannonState*)state)->unkB0 = (s8)(timer - framesThisStep);
            if (((DimCannonState*)state)->unkB0 <= 0)
            {
                (*gGameUIInterface)->initAirMeter(lbl_803DBF00, 0x5d5);
            }
        }
        else
        {
            if (!GameBit_Get(0xdb))
            {
                (*gGameUIInterface)->showNpcDialogue(0x4b9, 0x14, 0x8c, 1);
                GameBit_Set(0xdb, 1);
            }
            delta = (int)(-lbl_803DBF08 * (f32)padGetStickX(0));
            if (delta != 0)
            {
                s16 mag = *(s16*)((char*)vec + 0x2) < 0 ? -*(s16*)((char*)vec + 0x2) : *(s16*)((char*)vec + 0x2);
                if (mag > lbl_803DBF02 - lbl_803DBF04)
                {
                    int sc, sd;
                    sd = delta < 0 ? -1 : (delta > 0 ? 1 : 0);
                    sc = *(s16*)((char*)vec + 0x2) < 0 ? -1 : (*(s16*)((char*)vec + 0x2) > 0 ? 1 : 0);
                    if (sc == sd)
                    {
                        delta = delta * (lbl_803DBF02 - mag);
                        delta = delta / lbl_803DBF04;
                    }
                }
                *(s16*)((int)vec + 0x2) = (s16)(*(s16*)((int)vec + 0x2) + delta);
                Sfx_KeepAliveLoopedObjectSound((u32)obj, 0x1ff);
            }
            else
            {
                if (((DimCannonState*)state)->unkA8 != 0)
                {
                    Sfx_PlayFromObject((u32)obj, 0x1fe);
                }
            }
            ((DimCannonState*)state)->unkA8 = delta;
            if (((DimCannonState*)state)->aimYaw > 0)
            {
                ((DimCannonState*)state)->aimYaw -= framesThisStep;
            }
            if (((DimCannonState*)state)->aimPitch > 0)
            {
                ((DimCannonState*)state)->aimPitch -= framesThisStep;
            }
            if ((getButtonsHeld(0) & 0x100) && ((DimCannonState*)state)->aimYaw <= 0)
            {
                buttonDisable(0, 0x100);
                if (Player_GetCurrentMagic((int)player) >= 1)
                {
                    ((DimCannonState*)state)->unkAE += framesThisStep;
                    if (Sfx_IsPlayingFromObjectChannel((u32)obj, 2) == 0)
                    {
                        Sfx_PlayFromObject((u32)obj, 0x201);
                        Sfx_PlayFromObject((u32)obj, 0x202);
                    }
                }
                else
                {
                    Sfx_PlayFromObject((u32)obj, 0x40c);
                }
            }
            else
            {
                Sfx_StopObjectChannel((u32)obj, 2);
            }
            if (((DimCannonState*)state)->unkAE > lbl_803DBF00)
            {
                ((DimCannonState*)state)->unkAE = lbl_803DBF00;
            }
            (*gGameUIInterface)->runAirMeter(((DimCannonState*)state)->unkAE);
            ((DimCannonState*)state)->unk98 = (f32)((DimCannonState*)state)->unkAE * lbl_803DBEFC + lbl_803DBEF8;
            if ((getButtonsJustPressedIfNotBusy(0) & 0x100) ||
                ((DimCannonState*)state)->unkAE == lbl_803DBF00)
            {
                if (((DimCannonState*)state)->aimYaw <= 0 && Player_GetCurrentMagic((int)player) >= 1)
                {
                    buttonDisable(0, 0x100);
                    playerAddRemoveMagic(player, -1);
                    ((DimCannonState*)state)->unkAD = 1;
                    ((DimCannonState*)state)->unkAE = 0;
                }
            }
            DIMwooddoor_spawnShard(obj, 1);
            if (((GameObject*)obj)->anim.mapEventSlot == 0x13 && ((DimCannonState*)state)->unkB2 == 0 &&
                GameBit_Get(0xc17) && GameBit_Get(0xa21))
            {
                ((DimCannonState*)state)->unkB2 = 1;
                ((DimCannonState*)state)->unkB1 = 1;
            }
            {
                u8 b1 = ((DimCannonState*)state)->unkB1;
                if (b1 != 0)
                {
                    ((DimCannonState*)state)->unkB1 += framesThisStep;
                    if (((DimCannonState*)state)->unkB1 > 0x3c)
                    {
                        done = 1;
                    }
                }
            }
            if (done != 0 || (getButtonsJustPressed(0) & 0x200))
            {
                buttonDisable(0, 0x200);
                hudFn_8011f38c(0);
                (*gGameUIInterface)->airMeterSetShutdown();
                (*gCameraInterface)->setMode(0x42, 0, 1, 0, NULL, 0, 0xff);
                ((DimCannonState*)state)->fireState = 5;
                *(u8*)&((DimCannonState*)state)->unkB0 = 0x3c;
                animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
                if (Sfx_IsPlayingFromObjectChannel((u32)obj, 8) != 0)
                {
                    Sfx_IsPlayingFromObjectChannel((u32)obj, 0);
                }
                Sfx_StopObjectChannel((u32)obj, 2);
            }
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803DBEF4, timeDelta, NULL);
        }
    }
    else
    {
        s16* vec2;
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
        vec2 = objModelGetVecFn_800395d8(obj, 0);
        *(s16*)((char*)vec2 + 0x2) =
            (s16)(((GameObject*)obj)->anim.rotX - ((s8) * (s8*)((char*)src + 0x28) << 8));
        ((GameObject*)obj)->anim.rotX = (s16)((s8) * (s8*)((char*)src + 0x28) << 8);
        ((DimCannonState*)state)->fireState = 4;
    }

    return 0;
}
