/*
 * areafxemit (DLL 0x130) - a proximity particle-effect emitter object.
 *
 * Each tick areafxemit_update measures the distance from the emitter to
 * the player; once inside state->triggerRadius (a sentinel radius means
 * "always") it runs areafxemit_emitEffect. emitType selects how the fx
 * is spawned: 0 = world-positioned local fx (spawn flag 0x200001),
 * 1/2 = an acquired object resource (effectId + 0x58 / 0xAB) driven
 * through its vtable, 3 = local-space fx (flag 2), >=6 = pre-rotated
 * fx with type 6 world-positioned. emitCount controls the per-emit
 * particle count (>0) or, when <=0, a re-emit cooldown counted down in
 * frames; emitCount 0 self-suppresses after one emit. For emitType >= 4
 * crossing the trigger radius also fires a one-shot approach burst
 * (areafxemit_emitBurst, AREAFXEMIT_APPROACH_BURST_COUNT particles).
 *
 * Gating: state->enableBit (-1 = always) arms the emitter, state->stopBit
 * permanently suppresses it once set. Sequence event id 1 (areafxemit_SeqFn)
 * also triggers an emit.
 */
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"



enum {
    AREAFXEMIT_SEQEV_EMIT = 1
};

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
        range = (state)->extentX;                             \
        (pos)[0] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentY;                             \
        (pos)[1] = (f32)(s32)randomGetRange(-range, range);   \
        range = (state)->extentZ;                             \
        (pos)[2] = (f32)(s32)randomGetRange(-range, range);   \
    } while (0)

#define CF_EMITTER_SPAWN_PARTFX(obj, effectId, args, flags, modelId, arg6) \
    (*gPartfxInterface)->spawnObject((void *)(obj), (effectId), (args), (flags), (modelId), \
        (void *)(arg6))

#define CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, args, rot)      \
    do {                                                          \
        (rot)[0] = (state)->emitAngles[0];                       \
        (rot)[1] = (state)->emitAngles[1];                       \
        (rot)[2] = (state)->emitAngles[2];                       \
        if ((obj)->objAnim.parent != NULL) {                      \
            (rot)[2] += ((ObjAnimComponent *)(obj)->objAnim.parent)->rotZ; \
        }                                                         \
        vecRotateZXY((rot), (args)->pos);                         \
    } while (0)

#define CF_EMITTER_ADD_OBJECT_POSITION(obj, args)                 \
    do {                                                          \
        (args)->pos[0] += (obj)->objAnim.localPosX;               \
        (args)->pos[1] += (obj)->objAnim.localPosY;               \
        (args)->pos[2] += (obj)->objAnim.localPosZ;               \
    } while (0)

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

    if (type == AREAFXEMIT_SPAWN_LOCAL_WORLD)
    {
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args, rot);
                CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
            }
        }
        else
        {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args, rot);
            CF_EMITTER_ADD_OBJECT_POSITION(obj, &args);
            CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 0x200001, -1, 0);
        }
    }
    else if (type == AREAFXEMIT_SPAWN_OBJECT_RESOURCE)
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
    else if (type == AREAFXEMIT_SPAWN_OBJECT_RESOURCE_ALT)
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
    else if (type == AREAFXEMIT_SPAWN_LOCAL_OBJECT)
    {
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
                CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args, rot);
                CF_EMITTER_SPAWN_PARTFX(obj, state->effectId, &args, 2, -1, 0);
            }
        }
        else
        {
            CF_EMITTER_RANDOMIZE_OFFSET(state, args.pos);
            CF_EMITTER_ROTATE_FROM_LOCAL(obj, state, &args, rot);
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
        case AREAFXEMIT_SEQEV_EMIT:
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
                obj->emitCooldown = obj->emitCooldown - framesThisStep;
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

void areafxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

void areafxemit_free(AreaFxEmitObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void areafxemit_hitDetect(void)
{
}

void areafxemit_release(void)
{
}

void areafxemit_initialise(void)
{
}

int areafxemit_getExtraSize(void) { return sizeof(AreaFxEmitState); }
int areafxemit_getObjectTypeId(void) { return 0x0; }
