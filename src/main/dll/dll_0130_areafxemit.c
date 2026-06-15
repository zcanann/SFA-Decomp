#include "main/dll/CF/CFchuckobj.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint GameBit_Get(int eventId);
extern undefined4 FUN_80017748();
extern void vecRotateZXY(s16 * in, f32 * out);
extern u32 randomGetRange(int min, int max);
extern int Obj_GetPlayerObject(void);
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern f32 sqrtf(f32 value);

extern u8 framesThisStep;
extern f64 DOUBLE_803e4af8;
extern f32 FLOAT_803e4b00;
extern f32 lbl_803E3E68;
extern f32 lbl_803E3E6C;
extern f32 lbl_803E3E70;

#pragma dont_inline on
void areafxemit_emitBurst(AreaFxEmitObject* obj, int count)
{
    AreaFxEmitState* state;
    s16 i;
    struct
    {
        s16 hw[6];
        f32 vec[3];
    } args;

    state = obj->state;
    if (count > 0)
    {
        for (i = 0; i < count; i++)
        {
            {
                u16 sx = state->extentX;
                args.vec[0] = (f32)(s32)
                randomGetRange(-sx, sx);
            }
            {
                u16 sy = state->extentY;
                args.vec[1] = (f32)(s32)
                randomGetRange(-sy, sy);
            }
            {
                u16 sz = state->extentZ;
                args.vec[2] = (f32)(s32)
                randomGetRange(-sz, sz);
            }
            vecRotateZXY(state->emitAngles, args.vec);
            {
                u8 type = state->emitType;
                if (type == 4 || type == 6)
                {
                    args.vec[0] += obj->objAnim.localPosX;
                    args.vec[1] += obj->objAnim.localPosY;
                    args.vec[2] += obj->objAnim.localPosZ;
                    (*gPartfxInterface)->spawnObject(obj, state->effectId, &args, 0x200001, -1, NULL);
                }
                else
                {
                    (*gPartfxInterface)->spawnObject(obj, state->effectId, &args, 2, -1, NULL);
                }
            }
        }
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
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

/* Drift-recovery: add new fns with v1.0 names. */

typedef struct CFEmitterFxArgs
{
    u32 unk0;
    u32 unk4;
    f32 scale;
    f32 pos[3];
} CFEmitterFxArgs;

#define CF_EMITTER_RANDOMIZE_OFFSET(state, pos)               \
    do {                                                      \
        u16 range;                                            \
        range = (state)->extentX;                      \
        (pos)[0] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentY;                      \
        (pos)[1] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentZ;                      \
        (pos)[2] = (f32)(s32)randomGetRange(-range, range);   \
    } while (0)

#define CF_EMITTER_SPAWN_PARTFX(obj, effectId, args, flags, modelId, arg6) \
    (*gPartfxInterface)->spawnObject((void *)(obj), (effectId), (args), (flags), (modelId), \
        (void *)(arg6))

#define CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, args)            \
    do {                                                          \
        rot[0] = (state)->emitAngles[0];                         \
        rot[1] = (state)->emitAngles[1];                         \
        rot[2] = (state)->emitAngles[2];                         \
        if ((obj)->objAnim.parent != NULL) {                      \
            rot[2] += ((ObjAnimComponent *)(obj)->objAnim.parent)->rotZ; \
        }                                                         \
        vecRotateZXY(rot, (args)->pos);                        \
    } while (0)

#define CF_EMITTER_ADD_OBJECT_POSITION(obj, args)                 \
    do {                                                          \
        (args)->pos[0] += (obj)->objAnim.localPosX;               \
        (args)->pos[1] += (obj)->objAnim.localPosY;               \
        (args)->pos[2] += (obj)->objAnim.localPosZ;               \
    } while (0)

#pragma scheduling off
#pragma peephole off
void areafxemit_emitEffect(AreaFxEmitObject* obj)
{
    AreaFxEmitState* state;
    s16 i;
    s16 rot[3];
    u8 type;
    void* resource;
    CFEmitterFxArgs args;

    state = obj->state;
    args.scale = lbl_803E3E68;
    type = state->emitType;

    if (type == 0)
    {
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
                CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
            }
        }
        else
        {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
            CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
            CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
        }
    }
    else if (type == 1)
    {
        resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                (*(void (**)(AreaFxEmitObject*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
            }
        }
        else
        {
            (*(void (**)(AreaFxEmitObject*, int, int, int, int, int))(*(int*)resource + 4))(obj, 0, 0, 1, -1, 0);
        }
        Resource_Release(resource);
    }
    else if (type == 2)
    {
        resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                (*(void (**)(AreaFxEmitObject*, int, int, int, int, int, int))(*(int*)resource + 4))(
                    obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
            }
        }
        else
        {
            (*(void (**)(AreaFxEmitObject*, int, int, int, int, int, int))(*(int*)resource + 4))(
                obj, 0, 0, 1, -1, state->effectId & 0xff, 0);
        }
        Resource_Release(resource);
    }
    else if (type == 3)
    {
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
            }
        }
        else
        {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args);
            CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
        }
    }
    else if (type >= 6)
    {
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                vecRotateZXY(state->emitAngles, args.pos);
                if (state->emitType == 6)
                {
                    CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                    CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
                }
                else
                {
                    CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
                }
            }
        }
        else
        {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            vecRotateZXY(state->emitAngles, args.pos);
            if (state->emitType == 6)
            {
                CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
            }
            else
            {
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
            }
        }
    }
}

int areafxemit_SeqFn(AreaFxEmitObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    u8 i;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch ((s32)animUpdate->eventIds[i])
        {
        case 1:
            areafxemit_emitEffect(obj);
            break;
        }
    }
    return 0;
}

void areafxemit_update(AreaFxEmitObject* obj)
{
    AreaFxEmitState* state;
    ObjAnimComponent* player;
    f32 xDelta;
    f32 yDelta;
    f32 zDelta;
    f32 yy;
    f32 distance;
    f32 radius;

    state = obj->state;
    player = (ObjAnimComponent*)Obj_GetPlayerObject();
    if ((player != NULL) &&
        ((state->enableBit == -1) || (GameBit_Get(state->enableBit) != 0)))
    {
        switch (state->suppressed)
        {
        case 0:
            if (GameBit_Get(state->stopBit) != 0)
            {
                state->suppressed = 1;
            }
            if ((state->emitCount >= 0) ||
                ((state->emitCount < 0) && (obj->emitCooldown <= 0)))
            {
                xDelta = obj->objAnim.worldPosX - player->worldPosX;
                yDelta = obj->objAnim.worldPosY - player->worldPosY;
                zDelta = obj->objAnim.worldPosZ - player->worldPosZ;
                if (state->emitCount == 0)
                {
                    state->suppressed = 1;
                }
                yy = yDelta * yDelta;
                distance = sqrtf(yy + xDelta * xDelta + zDelta * zDelta);
                radius = state->triggerRadius;
                if (distance <= radius || lbl_803E3E6C == radius)
                {
                    if ((state->emitType >= 4) &&
                        ((state->lastDistance > radius && (lbl_803E3E6C != radius))))
                    {
                        areafxemit_emitBurst(obj, AREAFXEMIT_APPROACH_BURST_COUNT);
                    }
                    areafxemit_emitEffect(obj);
                }
                obj->emitCooldown = -state->emitCount;
                state->lastDistance = distance;
            }
            else if ((state->emitCount < 0) && (0 < obj->emitCooldown))
            {
                obj->emitCooldown = obj->emitCooldown - (u32)framesThisStep;
            }
            break;
        }
    }
}

void areafxemit_init(AreaFxEmitObject* obj, AreaFxEmitPlacement* setup)
{
    AreaFxEmitState* state;
    s16 angle;

    obj->seqCallback = areafxemit_SeqFn;
    state = obj->state;

    state->triggerRadius = (f32)((s32)setup->triggerRadius << 2);
    state->emitType = setup->emitType;
    state->effectId = setup->effectId;
    state->emitCount = setup->emitCount;
    state->enableBit = setup->enableBit;
    state->stopBit = setup->stopBit;
    state->suppressed = 0;
    state->extentX = (u16)(setup->extentX << 2);
    state->extentZ = (u16)(setup->extentZ << 2);
    state->extentY = (u16)(setup->extentY << 2);

    angle = (s16)(setup->initialRoll << 8);
    state->emitAngles[2] = angle;
    obj->objAnim.rotZ = angle;
    angle = (s16)(setup->initialPitch << 8);
    state->emitAngles[1] = angle;
    obj->objAnim.rotY = angle;
    angle = (s16)(setup->initialYaw << 8);
    state->emitAngles[0] = angle;
    obj->objAnim.rotX = angle;
    obj->objAnim.rootMotionScale = lbl_803E3E70;

    if (state->emitCount < 1)
    {
        obj->emitCooldown = state->emitCount;
    }
    else
    {
        obj->emitCooldown = 0;
    }

    if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0)
    {
        state->suppressed = 1;
    }
}

void lfxemitter_init(LfxEmitterObject* obj, LfxEmitterPlacement* setup);

void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void lfxemitter_initialise(void);

void areafxemit_free(AreaFxEmitObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void lfxemitter_free(LfxEmitterObject* obj);

void areafxemit_hitDetect(void)
{
}

void areafxemit_release(void)
{
}

void areafxemit_initialise(void)
{
}

void lfxemitter_render(void);

int areafxemit_getExtraSize(void) { return 0x20; }
int areafxemit_getObjectTypeId(void) { return 0x0; }
int lfxemitter_getExtraSize(void);
