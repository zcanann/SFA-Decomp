/*
 * exploded (DLL 0x166) - a single destructible debris shard object.
 *
 * On init the shard takes its model tag, scale, position and angles from
 * its placement map data; a randomized lifetime is rolled and physics are
 * armed when any initial velocity or acceleration is present. While active
 * (explodePhase 1) the per-frame update integrates linear velocity and spin
 * with gravity, bounces off a cached floor height, and settles to rest
 * (explodePhase 0); the lifetime countdown then fades alpha out and flags
 * the object for removal (flags06 |= 0x4000, explodePhase 2).
 */
#include "main/dll/drexplodable_types.h"
#include "main/dll/IM/IMicicle.h"
#include "main/game_object.h"

extern int randomGetRange(int min, int max);
extern void Model_GetVertexPosition(int* model, int i, f32* out);
extern f32 timeDelta;
extern void vecRotateYXZ(int, int);

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E43F4;
extern u8 framesThisStep;
extern f32 lbl_803E4428;
extern void Obj_TransformLocalPointByWorldMatrix(void* obj, void* state, f32* out, int flags);
extern void fn_80065684(double x, double y, double z, void* obj, f32* out, int flags);
extern f32 lbl_803E43F0;
extern f32 lbl_803E4400;
extern f32 lbl_803E4404;
extern f32 lbl_803E4408;
extern f32 lbl_803E4418;
extern f32 lbl_803E441C;
extern f32 lbl_803E4420;
extern f32 lbl_803E4424;

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

void exploded_free(void)
{
}

void exploded_hitDetect(void)
{
}

void exploded_release(void)
{
}

void exploded_initialise(void)
{
}

int exploded_getExtraSize(void) { return 0x6c; }

u8 exploded_setScale(int* obj) { return ((ExplodedObject*)obj)->state->explodePhase; }

void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E43F4);
}

u32 exploded_getObjectTypeId(ExplodedObject* obj) { return (obj->mapData->objectTypeTag << 11) | 0x400; }

void exploded_update(int* obj)
{
    ExplodedObject* o = (ExplodedObject*)obj;
    ExplodedObjectState* state = o->state;
    u8 stateVal = state->explodePhase;
    int flag;
    switch (stateVal)
    {
    case 0:
        break;
    case 1:
        if (exploded_stepDebrisPhysics(o, state) != 0)
        {
            state->explodePhase = 0;
        }
        break;
    case 2:
        break;
    }
    if (state->durationFrames != -1)
    {
        s32 elapsedFrames = state->elapsedFrames + framesThisStep;
        s32 durationFrames;
        state->elapsedFrames = elapsedFrames;
        durationFrames = state->durationFrames;
        if (elapsedFrames >= durationFrames)
        {
            state->durationFrames = -1;
            o->alpha = 0;
            o->flags06 = (s16)(o->flags06 | 0x4000);
            flag = 1;
            goto check;
        }
        else
        {
            s32 remainingFrames = durationFrames - state->elapsedFrames;
            if (remainingFrames < 0xff)
            {
                o->alpha = (u8)remainingFrames;
            }
        }
    }
    flag = 0;
check:
    if (flag != 0)
    {
        state->explodePhase = 2;
    }
}

void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra)
{
    ExplodedObjectState* state;
    obj->objectTypeTag = data->objectTypeTag;
    state = obj->state;
    obj->modelScale = (*(f32*)((char*)obj->modelData + 4) * (f32)(s32)data->scaleByte) / lbl_803E4428;
    exploded_initDebrisState(obj, data, extra, state);
    if (data->initialVelocityX != 0 ||
        data->initialVelocityY != 0 ||
        data->initialVelocityZ != 0 ||
        data->accelerationX != 0 ||
        data->accelerationY != 0 ||
        data->accelerationZ != 0)
    {
        state->explodePhase = 1;
    }
    else
    {
        state->explodePhase = 0;
    }
}

void exploded_initDebrisState(ExplodedObject* obj, ExplodedObjectMapData* data,
                              int computeModelCenter, ExplodedObjectState* state)
{
    obj->x = data->positionX;
    obj->y = data->positionY;
    obj->z = data->positionZ;

    if (computeModelCenter == 0)
    {
        register int* mesh;
        register int i;
        f32 v[6];
        f32 z;
        f32 k;

        z = lbl_803E43F0;
        state->localCenterX = z;
        state->localCenterY = z;
        state->localCenterZ = z;
        v[3] = z;
        v[4] = z;
        v[5] = z;

        mesh = *(int**)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks + (u32)data->objectTypeTag * 4));
        for (i = 0; i < *(u16*)((char*)mesh + 0xe4); i++)
        {
            Model_GetVertexPosition((int*)mesh, i, v);
            v[3] = v[0] + v[3];
            v[4] = v[1] + v[4];
            v[5] = v[2] + v[5];
        }

        state->localCenterX = v[3] * ((k = lbl_803E43F4) / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
        state->localCenterY = v[4] * (k / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
        state->localCenterZ = v[5] * (k / (f32)(u32) * (u16*)((char*)mesh + 0xe4));
    }

    state->initialLocalCenterX = state->localCenterX;
    state->initialLocalCenterY = state->localCenterY;
    state->initialLocalCenterZ = state->localCenterZ;
    exploded_seedDebrisMotion(obj, state, data);

    {
        f32 tv[3];
        tv[0] = state->localCenterX;
        tv[1] = state->localCenterY;
        tv[2] = state->localCenterZ;
        vecRotateYXZ((int)obj, (int)tv);
        tv[0] = tv[0] * obj->modelScale;
        tv[1] = tv[1] * obj->modelScale;
        tv[2] = tv[2] * obj->modelScale;
    }

    *((u8*)state + 0x67) = 255;
    state->physicsFlags = 0;
}

void exploded_seedDebrisMotion(ExplodedObject* obj, ExplodedObjectState* state, ExplodedObjectMapData* data)
{
    f32 floorY[2];
    f32 d1;

    floorY[0] = lbl_803E43F0;
    obj->angleX = data->initialAngleX;
    obj->angleY = data->initialAngleY;
    obj->angleZ = data->initialAngleZ;

    obj->velocityX = (f32)(s32)
    data->initialVelocityX / (d1 = lbl_803E4400);
    obj->velocityY = (f32)(s32)
    data->initialVelocityY / d1;
    obj->velocityZ = (f32)(s32)
    data->initialVelocityZ / d1;
    state->spinX = (f32)(s32)
    data->spinX;
    state->spinY = (f32)(s32)
    data->spinY;
    state->spinZ = (f32)(s32)
    data->spinZ;

    {
        u16 off = *(u16*)&data->floorOffset;
        if (off == 0)
        {
            fn_80065684((double)obj->x, (double)(obj->y - lbl_803E4404), (double)obj->z, obj, floorY, 0);
            state->floorHeight = obj->y - floorY[0];
        }
        else
        {
            state->floorHeight = obj->y + (f32)(s16)
            off;
        }
    }

    state->spinVelocityX = (f32)(s32)
    data->spinVelocityX / (d1 = lbl_803E4404);
    state->spinVelocityY = (f32)(s32)
    data->spinVelocityY / d1;
    state->spinVelocityZ = (f32)(s32)
    data->spinVelocityZ / d1;
    state->accelerationX = (f32)(s32)
    data->accelerationX / (d1 = lbl_803E4408);
    state->accelerationY = (f32)(s32)
    data->accelerationY / d1;
    state->accelerationZ = (f32)(s32)
    data->accelerationZ / d1;

    state->elapsedFrames = 0;
    if (*(u16*)&data->lifetimeFrames != 0)
    {
        state->durationFrames = *(u16*)&data->lifetimeFrames * ((int)randomGetRange(0, 100) + 100) / 200;
    }
    else
    {
        state->durationFrames = -1;
    }
}

int exploded_stepDebrisPhysics(ExplodedObject* obj, ExplodedObjectState* state)
{
    f32 stopped;
    f32 speed;
    f32 worldAfter[3];
    f32 worldBefore[3];

    stopped = lbl_803E43F0;
    Obj_TransformLocalPointByWorldMatrix(obj, state, worldBefore, 0);
    obj->velocityX = timeDelta * state->accelerationX + obj->velocityX;
    obj->velocityY = timeDelta * state->accelerationY + obj->velocityY;
    obj->velocityZ = timeDelta * state->accelerationZ + obj->velocityZ;
    state->spinX = timeDelta * state->spinVelocityX + state->spinX;
    state->spinY = timeDelta * state->spinVelocityY + state->spinY;
    state->spinZ = timeDelta * state->spinVelocityZ + state->spinZ;

    if (worldBefore[1] < state->floorHeight)
    {
        if (((obj->velocityY < *(f32*)&lbl_803E43F0) && ((state->physicsFlags & 4) != 0)) ||
            (lbl_803E43F0 == obj->velocityY))
        {
            f32 t;
            f32 k;
            t = lbl_803E43F0;
            state->accelerationY = t;
            state->spinVelocityZ = t;
            state->spinZ = t;
            state->spinVelocityY = t;
            state->spinY = t;
            state->spinVelocityX = t;
            state->spinX = t;
            obj->velocityY = t;
            k = lbl_803E4418;
            state->accelerationX = state->accelerationX * k;
            obj->velocityX = obj->velocityX * k;
            state->accelerationZ = state->accelerationZ * k;
            obj->velocityZ = obj->velocityZ * k;
            speed = obj->velocityX;
            speed = (speed >= t) ? speed : -speed;
            if (speed < lbl_803E441C)
            {
                speed = obj->velocityZ;
                speed = (speed >= lbl_803E43F0) ? speed : -speed;
                if (speed < lbl_803E441C)
                {
                    stopped = lbl_803E43F4;
                }
            }
        }
        if (obj->velocityY < lbl_803E43F0)
        {
            f32 k2;
            obj->velocityY = lbl_803E4420 * -obj->velocityY;
            k2 = lbl_803E4418;
            obj->velocityX = obj->velocityX * k2;
            obj->velocityZ = obj->velocityZ * k2;
            state->accelerationY = lbl_803E4424;
            state->spinVelocityZ = -state->spinVelocityZ;
        }
        state->physicsFlags |= 4;
    }
    else
    {
        state->physicsFlags &= ~4;
    }

    obj->angleX = (s16)(state->spinX * timeDelta + (f32)(s32)obj->angleX);
    obj->angleY = (s16)(state->spinY * timeDelta + (f32)(s32)obj->angleY);
    obj->angleZ = (s16)(state->spinZ * timeDelta + (f32)(s32)obj->angleZ);
    Obj_TransformLocalPointByWorldMatrix(obj, state, worldAfter, 0);
    worldAfter[0] = worldBefore[0] - worldAfter[0];
    worldAfter[1] = worldBefore[1] - worldAfter[1];
    worldAfter[2] = worldBefore[2] - worldAfter[2];
    obj->x = obj->x + worldAfter[0];
    obj->y = obj->y + worldAfter[1];
    obj->z = obj->z + worldAfter[2];
    obj->x = obj->velocityX * timeDelta + obj->x;
    obj->y = obj->velocityY * timeDelta + obj->y;
    obj->z = obj->velocityZ * timeDelta + obj->z;
    return (s32)stopped;
}
