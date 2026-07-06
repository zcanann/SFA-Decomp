/* DLL 0x166 - Exploded [801A39B4-801A39D0) */
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"


STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

extern void Model_GetVertexPosition(int model, int i, f32* out);

/* segment pragma-stack balance (re-split): */

#include "main/dll/IM/IMicicle.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/engine_shared.h"

/* ExplodedObjectState.explodePhase */
#define EXPLODED_PHASE_IDLE 0   /* settled; no physics */
#define EXPLODED_PHASE_ACTIVE 1 /* debris physics stepping until settled */
#define EXPLODED_PHASE_EXPIRED 2 /* lifetime elapsed; faded out */
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E43F4;
extern f32 lbl_803E4428;
extern void Obj_TransformLocalPointByWorldMatrix(void* obj, void* state, f32* out, int flags);
extern void fn_80065684(double x, double y, double z, void* obj, f32* out, int flags);
extern const f32 lbl_803E43F0;
extern f32 lbl_803E4404;
extern f32 gExplodedGroundFriction;
extern f32 gExplodedBounceRestitution;
extern f32 gExplodedGravity;

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

u8 exploded_setScale(int* obj) { return ((ExplodedObjectState*)(int*)((GameObject*)obj)->extra)->explodePhase; }

void exploded_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E43F4);
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
    case EXPLODED_PHASE_IDLE:
        break;
    case EXPLODED_PHASE_ACTIVE:
        if (exploded_stepDebrisPhysics(o, state) != 0)
        {
            state->explodePhase = EXPLODED_PHASE_IDLE;
        }
        break;
    case EXPLODED_PHASE_EXPIRED:
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
                o->alpha = remainingFrames;
            }
        }
    }
    flag = 0;
check:
    if (flag != 0)
    {
        state->explodePhase = EXPLODED_PHASE_EXPIRED;
    }
}

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */
void exploded_init(ExplodedObject* obj, ExplodedObjectMapData* data, int extra)
{
    ExplodedObjectState* state;
    obj->objectTypeTag = data->objectTypeTag;
    state = obj->state;
    obj->modelScale = (*(f32*)((char*)obj->modelData + 4) * (f32)(s32)
    data->scaleByte
    )
    /
    lbl_803E4428;
    exploded_initDebrisState(obj, data, extra, state);
    if (data->initialVelocityX != 0 ||
        data->initialVelocityY != 0 ||
        data->initialVelocityZ != 0 ||
        data->accelerationX != 0 ||
        data->accelerationY != 0 ||
        data->accelerationZ != 0)
    {
        state->explodePhase = EXPLODED_PHASE_ACTIVE;
    }
    else
    {
        state->explodePhase = EXPLODED_PHASE_IDLE;
    }
}

/* attractor_func0B: dispatch on obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */

void exploded_initDebrisState(ExplodedObject* obj, ExplodedObjectMapData* data,
                              int computeModelCenter, ExplodedObjectState* state)
{
    extern void Model_GetVertexPosition(int, int, f32*);
    extern void vecRotateYXZ(int, int);
    extern const f32 lbl_803E43F0;
    extern f32 lbl_803E43F4;

    obj->x = data->positionX;
    obj->y = data->positionY;
    obj->z = data->positionZ;

    if (computeModelCenter == 0)
    {
        register int i;
        register int mesh;
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

        mesh = *(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.banks + data->objectTypeTag * 4));
        for (i = 0; i < *(u16*)((char*)mesh + 0xe4); i++)
        {
            Model_GetVertexPosition(mesh, i, v);
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

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */
void exploded_seedDebrisMotion(ExplodedObject* obj, ExplodedObjectState* state, ExplodedObjectMapData* data)
{
    f32 floorY[2];

    floorY[0] = lbl_803E43F0;
    obj->angleX = data->initialAngleX;
    obj->angleY = data->initialAngleY;
    obj->angleZ = data->initialAngleZ;

    obj->velocityX = (f32)(s32)
    data->initialVelocityX / 100.0f;
    obj->velocityY = (f32)(s32)
    data->initialVelocityY / 100.0f;
    obj->velocityZ = (f32)(s32)
    data->initialVelocityZ / 100.0f;
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
    data->spinVelocityX / 10.0f;
    state->spinVelocityY = (f32)(s32)
    data->spinVelocityY / 10.0f;
    state->spinVelocityZ = (f32)(s32)
    data->spinVelocityZ / 10.0f;
    state->accelerationX = (f32)(s32)
    data->accelerationX / 1000.0f;
    state->accelerationY = (f32)(s32)
    data->accelerationY / 1000.0f;
    state->accelerationZ = (f32)(s32)
    data->accelerationZ / 1000.0f;

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

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
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
            state->accelerationX = state->accelerationX * (k = gExplodedGroundFriction);
            obj->velocityX = obj->velocityX * k;
            state->accelerationZ = state->accelerationZ * k;
            obj->velocityZ = obj->velocityZ * k;
            speed = (obj->velocityX >= t) ? obj->velocityX : -obj->velocityX;
            if (speed < 0.15f)
            {
                speed = (obj->velocityZ >= lbl_803E43F0) ? obj->velocityZ : -obj->velocityZ;
                if (speed < 0.15f)
                {
                    stopped = lbl_803E43F4;
                }
            }
        }
        if (obj->velocityY < lbl_803E43F0)
        {
            f32 k2;
            obj->velocityY = gExplodedBounceRestitution * -obj->velocityY;
            obj->velocityX = obj->velocityX * (k2 = gExplodedGroundFriction);
            obj->velocityZ = obj->velocityZ * k2;
            state->accelerationY = gExplodedGravity;
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
    return stopped;
}
