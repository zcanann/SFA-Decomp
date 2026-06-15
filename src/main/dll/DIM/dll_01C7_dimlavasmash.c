#include "main/dll/DIM/dimcannon_state.h"
#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIMlevcontrol.h"
#include "main/objseq.h"

extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006ba8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern int FUN_80017a98();
extern undefined4 FUN_8002fc3c();
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
extern f32 lbl_803E48F8;
STATIC_ASSERT(sizeof(DimCannonState) == 0xb4);
extern int ObjHits_GetPriorityHit(int obj, int* out, int* a, u32* b);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern int mapBlockFn_800606ec(int arg1, int idx);
extern int mapBlockFn_80060678(void);
extern int fn_8006070C(int arg1, int idx);
extern int Shader_getLayer(int layer, int idx);
extern unsigned long GameBit_Set(int eventId, int value);
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

void dimcannon_hitDetect(void);

#pragma scheduling off
#pragma peephole off
void dimlavasmash_free(void)
{
}

void dimlavasmash_hitDetect(void)
{
}

void dimlavasmash_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    if (state[2] == 2 && visible != 0)
    {
        ((void (*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E48F8);
    }
}

void dimlavasmash_update(int* obj)
{
    u8* sub;
    ObjHitsPriorityState* hitState;
    sub = ((GameObject*)obj)->extra;
    if (sub[2] == 1)
    {
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
    }
    else if (((GameObject*)obj)->unkF4 == 0)
    {
        if ((s8)sub[0] != -1)
        {
            (*gObjectTriggerInterface)->runSequence((s8)sub[0], obj, -1);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }
}

int dimlavasmash_getExtraSize(void) { return 0x3; }
int dimlavasmash_getObjectTypeId(void) { return 0x0; }

/* if (o->_X == K) return A; else return B; */

typedef struct DimlavasmashPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} DimlavasmashPlacement;

typedef struct DimlavasmashState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 state;
    u8 pad3[0x7 - 0x3];
    u8 unk7;
    u8 pad8[0x9 - 0x8];
    s8 unk9;
    s8 unkA;
    s8 unkB;
    u8 padC[0x10 - 0xC];
} DimlavasmashState;

/* dimcannon extra block (0xb4); the head is the per-cannonball column
 * arrays walked via state + i*4 (kept raw), this names the scalar tail. */

#pragma dont_inline on
#pragma opt_propagation off
void dimlavasmash_setBlockSurfaceFlags(int arg1, int arg2, int arg3)
{
    int m;
    int i;
    int j;
    int* block;
    int got;
    for (j = 0; j < (int)*(u16*)((char*)arg1 + 0x9a); j++)
    {
        block = (int*)mapBlockFn_800606ec(arg1, j);
        got = mapBlockFn_80060678();
        if (arg3 == got)
        {
            if (arg2 != 0)
            {
                *(u32*)(block + 0x10 / 4) &= ~2LL;
                *(u32*)(block + 0x10 / 4) &= ~1LL;
            }
            else
            {
                block[0x10 / 4] = block[0x10 / 4] | 2;
                block[0x10 / 4] = block[0x10 / 4] | 1;
            }
        }
    }
    for (i = 0, m = ~2; i < (int)*(u8*)((char*)arg1 + 0xa2); i++)
    {
        block = (int*)fn_8006070C(arg1, i);
        if (arg3 == (int)*(u8*)((char*)Shader_getLayer((int)block, 0) + 5))
        {
            if (arg2 != 0)
            {
                *(u32*)(block + 0x3c / 4) &= m;
            }
            else
            {
                block[0x3c / 4] = block[0x3c / 4] | 2;
            }
        }
    }
}
#pragma opt_propagation reset
#pragma dont_inline reset

int dimlavasmash_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int mapGetBlock(void);
    int* def;
    int hit;
    int block;
    int* state;
    ObjHitsPriorityState* hitState;
    state = ((GameObject*)obj)->extra;
    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (((DimlavasmashState*)state)->state == 0)
    {
        if (GameBit_Get(((DimlavasmashPlacement*)def)->unk20) != 0)
        {
            hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            hitState->flags |= 1;
            if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) != 0)
            {
                if (*(s16*)((char*)hit + 0x46) == 397)
                {
                    ((DimlavasmashState*)state)->state = 2;
                    Sfx_PlayFromObject(obj, SFXbaddie_eggsnatch_sniff1);
                    objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX,
                                        ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ);
                    block = mapGetBlock();
                    if ((void*)block != NULL)
                    {
                        dimlavasmash_setBlockSurfaceFlags(block, 1, ((DimlavasmashState*)state)->unk1);
                        dimlavasmash_setBlockSurfaceFlags(block, 0, ((DimlavasmashState*)state)->unk1 + 1);
                    }
                }
            }
        }
    }
    else
    {
        if (animUpdate->triggerCommand == 1)
        {
            GameBit_Set(((DimlavasmashPlacement*)def)->unk1E, 1);
            ((DimlavasmashState*)state)->state = 1;
        }
    }
    return ((DimlavasmashState*)state)->state == 0;
}

/* EN v1.0 0x801B30C8  size: 628b  Dimcannon constructor: handles the 0x1d6
 * sub-variant, else seeds the 10-slot trail particle array, installs the
 * sequence fn, acquires its model resource and applies map flags. */

/* EN v1.0 0x801B2C68  size: 1120b  Dimcannon per-frame state machine: idle ->
 * tracking -> firing -> spent, plus the 0x1d6 falling-debris sub-variant. */

/* EN v1.0 0x801B2550  size: 1504b  Dimcannon manned-control sequence: aims the
 * turret with the stick, charges with A, fires on release/full charge, and
 * exits on B or after the post-completion delay. */

typedef struct DimlavasmashObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} DimlavasmashObjectDef;

void dimlavasmash_init(s16* obj, s8* def)
{
    extern int* mapGetBlock(int idx);
    extern void dimlavasmash_setBlockSurfaceFlags(int* block, int mode, int v);
    ObjAnimComponent* objAnim;
    int* block;
    char* inner;
    ObjHitsPriorityState* hitState;

    objAnim = (ObjAnimComponent*)obj;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)def[0x18] << 8);
    ((GameObject*)obj)->animEventCallback = (void*)dimlavasmash_SeqFn;
    inner = ((GameObject*)obj)->extra;
    *(u8*)(inner + 1) = (u8)((DimlavasmashObjectDef*)def)->unk1A;
    *(s8*)(inner + 0) = (s8)((DimlavasmashObjectDef*)def)->unk1C;
    *(u8*)(inner + 2) = (u8)GameBit_Get(((DimlavasmashObjectDef*)def)->unk1E);
    if (*(u8*)(inner + 2) == 1)
    {
        block = mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                                ((GameObject*)obj)->anim.localPosZ));
        if (block != NULL)
        {
            dimlavasmash_setBlockSurfaceFlags(block, 1, *(u8*)(inner + 1));
            dimlavasmash_setBlockSurfaceFlags(block, 0, *(u8*)(inner + 1) + 1);
        }
    }
    objAnim->bankIndex = def[0x19];
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags &= ~1;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void dimlavasmash_release(void)
{
}

void dimlavasmash_initialise(void)
{
}
