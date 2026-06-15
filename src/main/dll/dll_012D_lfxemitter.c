#include "main/asset_load.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"

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
    byte spawnType;
    int emitter;
    int config;
    int* effectVtbl;
    short i;
    double in_f31;
    double roundBias;
    double in_ps31_1;
    ushort posBlock;
    undefined2 posBlock1;
    short posBlock2;
    u8 spawnParams[8];
    float local_58;
    float offX;
    float offY;
    float offZ;
    undefined4 local_48;
    uint randX;
    undefined4 local_40;
    uint randY;
    undefined4 local_38;
    uint randZ;
    float local_8;
    float fStack_4;

    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
    emitter = FUN_8028683c();
    config = *(int*)(emitter + 0xb8);
    local_58 = FLOAT_803e4b00;
    spawnType = *(byte*)(config + 8);
    if (spawnType == 0)
    {
        if (*(short*)(config + 0xc) < 1)
        {
            randZ = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
            offX = (f32)(s32)
            randZ;
            randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
            offY = (f32)(s32)
            randY;
            randX = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
            offZ = (f32)(s32)
            randX;
            posBlock = *(ushort*)(config + 0x1a);
            posBlock1 = *(undefined2*)(config + 0x1c);
            posBlock2 = *(short*)(config + 0x1e);
            if (*(int*)(emitter + 0x30) != 0)
            {
                posBlock2 = posBlock2 + *(short*)(*(int*)(emitter + 0x30) + 4);
            }
            FUN_80017748(&posBlock, &offX);
            offX = offX + *(float*)(emitter + 0xc);
            offY = offY + *(float*)(emitter + 0x10);
            offZ = offZ + *(float*)(emitter + 0x14);
            (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                             spawnParams, 0x200001, -1, NULL);
        }
        else
        {
            roundBias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(config + 0xc); i = i + 1)
            {
                randX = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
                offX = (float)((double)CONCAT44(0x43300000, randX) - roundBias);
                randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
                offY = (float)((double)CONCAT44(0x43300000, randY) - roundBias);
                randZ = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
                offZ = (float)((double)CONCAT44(0x43300000, randZ) - roundBias);
                posBlock = *(ushort*)(config + 0x1a);
                posBlock1 = *(undefined2*)(config + 0x1c);
                posBlock2 = *(short*)(config + 0x1e);
                if (*(int*)(emitter + 0x30) != 0)
                {
                    posBlock2 = posBlock2 + *(short*)(*(int*)(emitter + 0x30) + 4);
                }
                FUN_80017748(&posBlock, &offX);
                offX = offX + *(float*)(emitter + 0xc);
                offY = offY + *(float*)(emitter + 0x10);
                offZ = offZ + *(float*)(emitter + 0x14);
                (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                 spawnParams, 0x200001, -1, NULL);
            }
        }
    }
    else if (spawnType == 1)
    {
        effectVtbl = (int*)FUN_80006b14(*(ushort*)(config + 10) + 0x58 & 0xffff);
        if (*(short*)(config + 0xc) < 1)
        {
            (**(code**)(*effectVtbl + 4))(emitter, 0, 0, 1, 0xffffffff, 0);
        }
        else
        {
            for (i = 0; i < *(short*)(config + 0xc); i = i + 1)
            {
                (**(code**)(*effectVtbl + 4))(emitter, 0, 0, 1, 0xffffffff, 0);
            }
        }
        FUN_80006b0c((undefined*)effectVtbl);
    }
    else if (spawnType == 2)
    {
        effectVtbl = (int*)FUN_80006b14(*(ushort*)(config + 10) + 0xab & 0xffff);
        if (*(short*)(config + 0xc) < 1)
        {
            (**(code**)(*effectVtbl + 4))(emitter, 0, 0, 1, 0xffffffff, *(ushort*)(config + 10) & 0xff, 0);
        }
        else
        {
            for (i = 0; i < *(short*)(config + 0xc); i = i + 1)
            {
                (**(code**)(*effectVtbl + 4))(emitter, 0, 0, 1, 0xffffffff, *(ushort*)(config + 10) & 0xff, 0);
            }
        }
        FUN_80006b0c((undefined*)effectVtbl);
    }
    else if (spawnType == 3)
    {
        if (*(short*)(config + 0xc) < 1)
        {
            randZ = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
            offX = (f32)(s32)
            randZ;
            randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
            offY = (f32)(s32)
            randY;
            randX = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
            offZ = (f32)(s32)
            randX;
            posBlock = *(ushort*)(config + 0x1a);
            posBlock1 = *(undefined2*)(config + 0x1c);
            posBlock2 = *(short*)(config + 0x1e);
            if (*(int*)(emitter + 0x30) != 0)
            {
                posBlock2 = posBlock2 + *(short*)(*(int*)(emitter + 0x30) + 4);
            }
            FUN_80017748(&posBlock, &offX);
            (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                             spawnParams, 2, -1, NULL);
        }
        else
        {
            roundBias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(config + 0xc); i = i + 1)
            {
                randZ = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
                offX = (float)((double)CONCAT44(0x43300000, randZ) - roundBias);
                randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
                offY = (float)((double)CONCAT44(0x43300000, randY) - roundBias);
                randX = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
                offZ = (float)((double)CONCAT44(0x43300000, randX) - roundBias);
                posBlock = *(ushort*)(config + 0x1a);
                posBlock1 = *(undefined2*)(config + 0x1c);
                posBlock2 = *(short*)(config + 0x1e);
                if (*(int*)(emitter + 0x30) != 0)
                {
                    posBlock2 = posBlock2 + *(short*)(*(int*)(emitter + 0x30) + 4);
                }
                FUN_80017748(&posBlock, &offX);
                (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                 spawnParams, 2, -1, NULL);
            }
        }
    }
    else if (5 < spawnType)
    {
        if (*(short*)(config + 0xc) < 1)
        {
            randZ = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
            offX = (f32)(s32)
            randZ;
            randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
            offY = (f32)(s32)
            randY;
            randX = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
            offZ = (f32)(s32)
            randX;
            FUN_80017748((ushort*)(config + 0x1a), &offX);
            if (*(char*)(config + 8) == '\x06')
            {
                offX = offX + *(float*)(emitter + 0xc);
                offY = offY + *(float*)(emitter + 0x10);
                offZ = offZ + *(float*)(emitter + 0x14);
                (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                 spawnParams, 0x200001, -1, NULL);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                 spawnParams, 2, -1, NULL);
            }
        }
        else
        {
            roundBias = DOUBLE_803e4af8;
            for (i = 0; i < *(short*)(config + 0xc); i = i + 1)
            {
                randZ = randomGetRange(-(uint) * (ushort*)(config + 0x14), (uint) * (ushort*)(config + 0x14));
                offX = (float)((double)CONCAT44(0x43300000, randZ) - roundBias);
                randY = randomGetRange(-(uint) * (ushort*)(config + 0x18), (uint) * (ushort*)(config + 0x18));
                offY = (float)((double)CONCAT44(0x43300000, randY) - roundBias);
                randX = randomGetRange(-(uint) * (ushort*)(config + 0x16), (uint) * (ushort*)(config + 0x16));
                offZ = (float)((double)CONCAT44(0x43300000, randX) - roundBias);
                FUN_80017748((ushort*)(config + 0x1a), &offX);
                if (*(char*)(config + 8) == '\x06')
                {
                    offX = offX + *(float*)(emitter + 0xc);
                    offY = offY + *(float*)(emitter + 0x10);
                    offZ = offZ + *(float*)(emitter + 0x14);
                    (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                     spawnParams, 0x200001, -1, NULL);
                }
                else
                {
                    (*gPartfxInterface)->spawnObject((void*)emitter, *(undefined2*)(config + 10),
                                                     spawnParams, 2, -1, NULL);
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
