#include "main/asset_load.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/dll/CF/warp_pad.h"
#include "main/objseq.h"
#include "main/resource.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void Obj_FreeObject(int obj);
extern int Obj_GetPlayerObject(void);
extern int Curve_AdvanceAlongPath(RomCurveWalker *curve, f32 progress);
extern void* mmAlloc(int size, int heap, int flags);
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern u8 framesThisStep;
extern f32 timeDelta;
extern f64 DOUBLE_803e4af8;
extern f32 FLOAT_803e4b00;
extern f32 lbl_803E3E78;
extern f32 lbl_803E3E7C;
extern f32 lbl_803E3E80;
extern f32 lbl_803E3E84;
extern f32 lbl_803E3E88;

#pragma scheduling on
#pragma peephole on
extern u8 lbl_803AC7B0[];
extern void mm_free(void* p);

void FUN_8018f650(void)
{
    byte bVar1;
    int iVar2;
    int* piVar3;
    short sVar4;
    int iVar5;
    double in_f31;
    double dVar6;
    double in_ps31_1;
    ushort local_68;
    undefined2 local_66;
    short local_64;
    u8 auStack_60[8];
    float local_58;
    float local_54;
    float local_50;
    float local_4c;
    undefined4 local_48;
    uint uStack_44;
    undefined4 local_40;
    uint uStack_3c;
    undefined4 local_38;
    uint uStack_34;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    iVar2 = FUN_8028683c();
    iVar5 = *(int*)(iVar2 + 0xb8);
    local_58 = FLOAT_803e4b00;
    bVar1 = *(byte*)(iVar5 + 8);
    if (bVar1 == 0)
    {
        if (*(short*)(iVar5 + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            local_68 = *(ushort*)(iVar5 + 0x1a);
            local_66 = *(undefined2*)(iVar5 + 0x1c);
            local_64 = *(short*)(iVar5 + 0x1e);
            if (*(int*)(iVar2 + 0x30) != 0)
            {
                local_64 = local_64 + *(short*)(*(int*)(iVar2 + 0x30) + 4);
            }
            FUN_80017748(&local_68, &local_54);
            local_54 = local_54 + *(float*)(iVar2 + 0xc);
            local_50 = local_50 + *(float*)(iVar2 + 0x10);
            local_4c = local_4c + *(float*)(iVar2 + 0x14);
            (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                             auStack_60, 0x200001, -1, NULL);
        }
        else
        {
            dVar6 = DOUBLE_803e4af8;
            for (sVar4 = 0; sVar4 < *(short*)(iVar5 + 0xc); sVar4 = sVar4 + 1)
            {
                uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_44) - dVar6);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - dVar6);
                uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_34) - dVar6);
                local_68 = *(ushort*)(iVar5 + 0x1a);
                local_66 = *(undefined2*)(iVar5 + 0x1c);
                local_64 = *(short*)(iVar5 + 0x1e);
                if (*(int*)(iVar2 + 0x30) != 0)
                {
                    local_64 = local_64 + *(short*)(*(int*)(iVar2 + 0x30) + 4);
                }
                FUN_80017748(&local_68, &local_54);
                local_54 = local_54 + *(float*)(iVar2 + 0xc);
                local_50 = local_50 + *(float*)(iVar2 + 0x10);
                local_4c = local_4c + *(float*)(iVar2 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                 auStack_60, 0x200001, -1, NULL);
            }
        }
    }
    else if (bVar1 == 1)
    {
        piVar3 = (int*)FUN_80006b14(*(ushort*)(iVar5 + 10) + 0x58 & 0xffff);
        if (*(short*)(iVar5 + 0xc) < 1)
        {
            (**(code**)(*piVar3 + 4))(iVar2, 0, 0, 1, 0xffffffff, 0);
        }
        else
        {
            for (sVar4 = 0; sVar4 < *(short*)(iVar5 + 0xc); sVar4 = sVar4 + 1)
            {
                (**(code**)(*piVar3 + 4))(iVar2, 0, 0, 1, 0xffffffff, 0);
            }
        }
        FUN_80006b0c((undefined*)piVar3);
    }
    else if (bVar1 == 2)
    {
        piVar3 = (int*)FUN_80006b14(*(ushort*)(iVar5 + 10) + 0xab & 0xffff);
        if (*(short*)(iVar5 + 0xc) < 1)
        {
            (**(code**)(*piVar3 + 4))(iVar2, 0, 0, 1, 0xffffffff, *(ushort*)(iVar5 + 10) & 0xff, 0);
        }
        else
        {
            for (sVar4 = 0; sVar4 < *(short*)(iVar5 + 0xc); sVar4 = sVar4 + 1)
            {
                (**(code**)(*piVar3 + 4))(iVar2, 0, 0, 1, 0xffffffff, *(ushort*)(iVar5 + 10) & 0xff, 0);
            }
        }
        FUN_80006b0c((undefined*)piVar3);
    }
    else if (bVar1 == 3)
    {
        if (*(short*)(iVar5 + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            local_68 = *(ushort*)(iVar5 + 0x1a);
            local_66 = *(undefined2*)(iVar5 + 0x1c);
            local_64 = *(short*)(iVar5 + 0x1e);
            if (*(int*)(iVar2 + 0x30) != 0)
            {
                local_64 = local_64 + *(short*)(*(int*)(iVar2 + 0x30) + 4);
            }
            FUN_80017748(&local_68, &local_54);
            (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                             auStack_60, 2, -1, NULL);
        }
        else
        {
            dVar6 = DOUBLE_803e4af8;
            for (sVar4 = 0; sVar4 < *(short*)(iVar5 + 0xc); sVar4 = sVar4 + 1)
            {
                uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_34) - dVar6);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - dVar6);
                uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_44) - dVar6);
                local_68 = *(ushort*)(iVar5 + 0x1a);
                local_66 = *(undefined2*)(iVar5 + 0x1c);
                local_64 = *(short*)(iVar5 + 0x1e);
                if (*(int*)(iVar2 + 0x30) != 0)
                {
                    local_64 = local_64 + *(short*)(*(int*)(iVar2 + 0x30) + 4);
                }
                FUN_80017748(&local_68, &local_54);
                (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                 auStack_60, 2, -1, NULL);
            }
        }
    }
    else if (5 < bVar1)
    {
        if (*(short*)(iVar5 + 0xc) < 1)
        {
            uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
            local_54 = (f32)(s32)
            uStack_34;
            uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
            local_50 = (f32)(s32)
            uStack_3c;
            uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
            local_4c = (f32)(s32)
            uStack_44;
            FUN_80017748((ushort*)(iVar5 + 0x1a), &local_54);
            if (*(char*)(iVar5 + 8) == '\x06')
            {
                local_54 = local_54 + *(float*)(iVar2 + 0xc);
                local_50 = local_50 + *(float*)(iVar2 + 0x10);
                local_4c = local_4c + *(float*)(iVar2 + 0x14);
                (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                 auStack_60, 0x200001, -1, NULL);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                 auStack_60, 2, -1, NULL);
            }
        }
        else
        {
            dVar6 = DOUBLE_803e4af8;
            for (sVar4 = 0; sVar4 < *(short*)(iVar5 + 0xc); sVar4 = sVar4 + 1)
            {
                uStack_34 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x14), (uint) * (ushort*)(iVar5 + 0x14));
                local_54 = (float)((double)CONCAT44(0x43300000, uStack_34) - dVar6);
                uStack_3c = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x18), (uint) * (ushort*)(iVar5 + 0x18));
                local_50 = (float)((double)CONCAT44(0x43300000, uStack_3c) - dVar6);
                uStack_44 = randomGetRange(-(uint) * (ushort*)(iVar5 + 0x16), (uint) * (ushort*)(iVar5 + 0x16));
                local_4c = (float)((double)CONCAT44(0x43300000, uStack_44) - dVar6);
                FUN_80017748((ushort*)(iVar5 + 0x1a), &local_54);
                if (*(char*)(iVar5 + 8) == '\x06')
                {
                    local_54 = local_54 + *(float*)(iVar2 + 0xc);
                    local_50 = local_50 + *(float*)(iVar2 + 0x10);
                    local_4c = local_4c + *(float*)(iVar2 + 0x14);
                    (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                     auStack_60, 0x200001, -1, NULL);
                }
                else
                {
                    (*gPartfxInterface)->spawnObject((void*)iVar2, *(undefined2*)(iVar5 + 10),
                                                     auStack_60, 2, -1, NULL);
                }
            }
        }
    }
    FUN_80286888();
    return;
}

void warpPadFn_8019042c(int obj);

#pragma scheduling off
#pragma peephole off
void lfxemitter_init(LfxEmitterObject* obj, LfxEmitterPlacement* setup)
{
    LfxEmitterState* state;
    int curveFlags;

    state = obj->state;
    curveFlags = 0x21;
    obj->objAnim.rootMotionScale = lbl_803E3E80 * obj->objAnim.modelInstance->rootMotionScaleBase;

    state->configIndex = setup->configIndex;
    state->lifeTimer = setup->lifeTimer;
    state->unk114 = -2;
    state->enableBit = setup->enableBit;
    state->spinRoll = setup->spinRoll;
    state->spinPitch = setup->spinPitch;
    state->spinYaw = setup->spinYaw;
    obj->objAnim.localPosX = setup->initialX;
    obj->objAnim.localPosY = setup->initialY;
    obj->objAnim.localPosZ = setup->initialZ;

    if (state->lifeTimer != 0)
    {
        state->hasLifeTimer = 1;
    }
    else
    {
        state->hasLifeTimer = 0;
    }

    if (setup->followCurve != 0)
    {
        state->flags = state->flags | LFXEMITTER_FLAG_FOLLOW_CURVE;
        state->curveSpeed = (f32)setup->curveSpeed / lbl_803E3E84;
        (*gRomCurveInterface)->initCurve(&state->curve, obj, lbl_803E3E88, &curveFlags, -1);
    }
    ObjGroup_AddObject((int)obj, LFXEMITTER_OBJ_GROUP);
}

int lfxemitter_setScale(void) { return -1; }

void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void lfxemitter_initialise(void)
{
    *(s16*)(lbl_803AC7B0 + 14) = 10000;
}

int lfxemitter_func0B(LfxEmitterObject* obj)
{
    LfxEmitterState* state = obj->state;
    int v = (int)state->config;
    return (u32)(-v | v) >> 31;
}

void fn_8018FF48(undefined2* src, undefined2* dst)
{
    *dst = *src;
    dst[1] = src[1];
    ((s16*)dst)[2] = ((s16*)src)[2];
    ((s16*)dst)[3] = ((s16*)src)[3];
    ((s16*)dst)[4] = ((s16*)src)[4];
    ((s16*)dst)[5] = ((s16*)src)[5];
    ((s16*)dst)[6] = ((s16*)src)[6];
    dst[7] = src[7];
    *(u8*)(dst + 9) = *(u8*)(src + 9);
    *(u8*)((int)dst + 0x13) = *(u8*)((int)src + 0x13);
    *(u8*)((int)dst + 0x1b) = *(u8*)((int)src + 0x1b);
    *(u8*)(dst + 0xe) = *(u8*)(src + 0xe);
    *(u8*)((int)dst + 0x1d) = *(u8*)((int)src + 0x1d);
    *(u8*)(dst + 0xf) = *(u8*)(src + 0xf);
    *(u8*)((int)dst + 0x1f) = *(u8*)((int)src + 0x1f);
    *(u8*)(dst + 0x10) = *(u8*)(src + 0x10);
    *(u8*)((int)dst + 0x21) = *(u8*)((int)src + 0x21);
    *(u8*)(dst + 0x11) = *(u8*)(src + 0x11);
    *(u8*)((int)dst + 0x15) = *(u8*)((int)src + 0x15);
    *(u8*)((int)dst + 0x23) = *(u8*)((int)src + 0x23);
    *(u8*)(dst + 0xb) = *(u8*)(src + 0xb);
    *(u8*)(dst + 0x12) = *(u8*)(src + 0x12);
    *(u8*)((int)dst + 0x17) = *(u8*)((int)src + 0x17);
    *(u8*)((int)dst + 0x25) = *(u8*)((int)src + 0x25);
    *(u8*)(dst + 0xc) = *(u8*)(src + 0xc);
    *(u8*)(dst + 0x13) = *(u8*)(src + 0x13);
    *(u8*)((int)dst + 0x19) = *(u8*)((int)src + 0x19);
    *(u8*)((int)dst + 0x27) = *(u8*)((int)src + 0x27);
    *(u8*)(dst + 0xd) = *(u8*)(src + 0xd);
    *(u8*)(dst + 0x14) = *(u8*)(src + 0x14);
}

void lfxemitter_update(LfxEmitterObject* obj)
{
    LfxEmitterState* state;
    ObjAnimComponent* player;

    state = obj->state;
    player = (ObjAnimComponent*)Obj_GetPlayerObject();

    obj->objAnim.rotX += state->spinYaw;
    obj->objAnim.rotZ += state->spinRoll;
    obj->objAnim.rotY += state->spinPitch;

    if ((state->flags & LFXEMITTER_FLAG_FOLLOW_CURVE) != 0)
    {
        if ((Curve_AdvanceAlongPath(&state->curve, state->curveSpeed) != 0) ||
            (state->curve.atSegmentEnd != 0))
        {
            (*gRomCurveInterface)->goNextPoint(&state->curve);
        }
        obj->objAnim.localPosX = state->curve.posX;
        obj->objAnim.localPosY = state->curve.posY;
        obj->objAnim.localPosZ = state->curve.posZ;
    }
    else
    {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        if (((state->flags & LFXEMITTER_FLAG_DAMP_Y_VELOCITY) != 0) && (obj->objAnim.velocityY > lbl_803E3E78))
        {
            obj->objAnim.velocityY = lbl_803E3E7C * timeDelta + obj->objAnim.velocityY;
        }
    }

    if ((player != NULL) &&
        ((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0)))
    {
        if (state->hasLifeTimer != 0)
        {
            state->lifeTimer -= framesThisStep;
            if (state->lifeTimer <= 0)
            {
                Obj_FreeObject((int)obj);
                return;
            }
        }
        if (state->configLoaded == 0)
        {
            if ((state != NULL) && (state->configIndex == (*(u16*)(lbl_803AC7B0 + 0xe) - 1)))
            {
                state->config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                if (state->config != NULL)
                {
                    fn_8018FF48((undefined2*)lbl_803AC7B0, (undefined2*)state->config);
                }
            }
            else
            {
                state->config = mmAlloc(LFXEMITTER_CONFIG_BYTES, 0x12, 0);
                getTabEntry(state->config, 0xc, state->configIndex * LFXEMITTER_CONFIG_BYTES, LFXEMITTER_CONFIG_BYTES);
                if (state->config != NULL)
                {
                    fn_8018FF48((undefined2*)state->config, (undefined2*)lbl_803AC7B0);
                }
            }
            state->configLoaded = 1;
        }
    }
}

void warpPadPlayerStandingOn(int obj);

void lfxemitter_free(LfxEmitterObject* obj)
{
    LfxEmitterState* state = obj->state;
    int* ptr = (int*)state->config;
    if (ptr != NULL)
    {
        mm_free(ptr);
    }
    ObjGroup_RemoveObject((int)obj, LFXEMITTER_OBJ_GROUP);
}

void fxemit_release(void);

void lfxemitter_render(void)
{
}

void lfxemitter_hitDetect(void)
{
}

void lfxemitter_release(void)
{
}

int areafxemit_getExtraSize(void);
int lfxemitter_getExtraSize(void) { return 0x124; }
int lfxemitter_getObjectTypeId(void) { return 0x0; }
