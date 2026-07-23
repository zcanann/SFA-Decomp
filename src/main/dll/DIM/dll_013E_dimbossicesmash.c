/* DLL 0x13E - DIMBossIceSmash [0x80194890-0x80197190): spinning ice shards
 * launched during the DIM boss fight.  Each shard integrates velocity and
 * rotation, optionally follows a path-control surface bounce, fades over a
 * per-setup lifetime window, and emits two trail particles per frame while
 * fully opaque. */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/object.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

u8 lbl_803DBDF8[8] = {0x40, 0x80, 0, 0, 0, 0, 0, 0};

/* ice-debris particle spawned along the smash sweep between the previous and current position */
#define DIMBOSSICESMASH_PARTFX 1000

typedef struct DimbossicesmashPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 spawnRotX;
    s16 spawnRotY;
    s16 spawnRotZ;
    s16 velocityX;  /* launch speed (homing) or velocity X (*100) */
    s16 velocityY;  /* velocity Y (*100) */
    s16 velocityZ;  /* velocity Z (*100) */
    s16 gravityX;  /* gravity X (*1000) */
    s16 gravityY;  /* gravity Y (*1000) */
    s16 gravityZ;  /* gravity Z (*1000) */
    s16 rotVelX;  /* rotation velocity X */
    s16 rotVelY;  /* rotation velocity Y */
    s16 rotVelZ;  /* rotation velocity Z */
    s16 rotGravityX;  /* rotation gravity X (*10) */
    s16 rotGravityY;  /* rotation gravity Y (*10) */
    s16 rotGravityZ;  /* rotation gravity Z (*10) */
    u16 lifetime;  /* lifetime in frames */
    u16 fadeStartFrame;  /* fade start frame */
    u8 flags;   /* bit0=homing, bit1=path-control, bit2=trail particles */
    u8 pad3D[0x3E - 0x3D];
    s16 activateGameBit;  /* gamebit to set on activation */
    s16 triggerGameBit;  /* gamebit to test for activation */
    s16 homingTargetX;  /* homing target X */
    s16 homingTargetY;  /* homing target Y */
    s16 homingTargetZ;  /* homing target Z */
} DimbossicesmashPlacement;

u8 lbl_803DDB00;

u8 lbl_80322368[0xC] = {0};

/* seed the icesmash launch state from the setup record: spawn position/rotation,
 * launch velocity (optionally homing on the target point), rotation velocities
 * and the gravity/clamp direction flags. */
void dimbossicesmash_initLaunchState(GameObject* obj, u8* state, u8* setup)
{
    f32 vx, vy, vz;
    f32 spd, len;

    obj->anim.localPosX = ((DimBossIceSmashState*)state)->spawnScaleX * obj->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posX;
    obj->anim.localPosY = ((DimBossIceSmashState*)state)->spawnScaleY * obj->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posY;
    obj->anim.localPosZ = ((DimBossIceSmashState*)state)->spawnScaleZ * obj->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posZ;
    obj->anim.rotX = ((DimbossicesmashPlacement*)setup)->spawnRotX;
    obj->anim.rotY = ((DimbossicesmashPlacement*)setup)->spawnRotY;
    obj->anim.rotZ = ((DimbossicesmashPlacement*)setup)->spawnRotZ;
    if ((((DimbossicesmashPlacement*)setup)->flags & 1) != 0)
    {
        spd = (f32)((DimbossicesmashPlacement*)setup)->velocityX / 100.0f;
        vx = obj->anim.localPosX - (f32)((DimbossicesmashPlacement*)setup)->homingTargetX;
        vy = obj->anim.localPosY - (f32)((DimbossicesmashPlacement*)setup)->homingTargetY;
        vz = obj->anim.localPosZ - (f32)((DimbossicesmashPlacement*)setup)->homingTargetZ;
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (0.0f != len)
        {
            vx = vx / len;
            vy = vy / len;
            vz = vz / len;
        }
        obj->anim.velocityX = spd * vx;
        obj->anim.velocityY = spd * vy;
        obj->anim.velocityZ = spd * vz;
    }
    else
    {
        obj->anim.velocityX = (f32)((DimbossicesmashPlacement*)setup)->velocityX / 100.0f;
        obj->anim.velocityY = (f32)((DimbossicesmashPlacement*)setup)->velocityY / 100.0f;
        obj->anim.velocityZ = (f32)((DimbossicesmashPlacement*)setup)->velocityZ / 100.0f;
    }
    ((DimBossIceSmashState*)state)->angVelX = (f32)((DimbossicesmashPlacement*)setup)->rotVelX;
    ((DimBossIceSmashState*)state)->angVelY = (f32)((DimbossicesmashPlacement*)setup)->rotVelY;
    ((DimBossIceSmashState*)state)->angVelZ = (f32)((DimbossicesmashPlacement*)setup)->rotVelZ;
    if (obj->anim.velocityX > 0.0f)
    {
        state[0x29f] = state[0x29f] | 1;
    }
    if (obj->anim.velocityZ > 0.0f)
    {
        state[0x29f] = state[0x29f] | 2;
    }
    if (((DimBossIceSmashState*)state)->angVelX > 0.0f)
    {
        state[0x29f] = state[0x29f] | 4;
    }
    if (((DimBossIceSmashState*)state)->angVelY > 0.0f)
    {
        state[0x29f] = state[0x29f] | 8;
    }
    if (((DimBossIceSmashState*)state)->angVelZ > 0.0f)
    {
        state[0x29f] = state[0x29f] | 0x10;
    }
    ((DimBossIceSmashState*)state)->angAccelX = (f32)((DimbossicesmashPlacement*)setup)->rotGravityX / 10.0f;
    ((DimBossIceSmashState*)state)->angAccelY = (f32)((DimbossicesmashPlacement*)setup)->rotGravityY / 10.0f;
    ((DimBossIceSmashState*)state)->angAccelZ = (f32)((DimbossicesmashPlacement*)setup)->rotGravityZ / 10.0f;
    ((DimBossIceSmashState*)state)->accelX = (f32)((DimbossicesmashPlacement*)setup)->gravityX / 1000.0f;
    ((DimBossIceSmashState*)state)->accelY = (f32)((DimbossicesmashPlacement*)setup)->gravityY / 1000.0f;
    ((DimBossIceSmashState*)state)->accelZ = (f32)((DimbossicesmashPlacement*)setup)->gravityZ / 1000.0f;
    ((DimBossIceSmashState*)state)->timer = 0;
}

int DIMBossIceSmash_getExtraSize(void) { return 0x2a0; }

u32 DIMBossIceSmash_getObjectTypeId(GameObject* obj) { return (*((u8*)obj->anim.placementData + 0x18) << 11) | 0x400; }

void DIMBossIceSmash_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void DIMBossIceSmash_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
}

void DIMBossIceSmash_hitDetect(void)
{
}

/* gate on the trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */
void DIMBossIceSmash_update(GameObject* obj)
{
    u8* state = obj->extra;
    u8 flags = state[0x29e];
    u8* setup;
    u32 triggerBit;
    int alphaVal;
    s16 cnt;
    int fadeDuration;
    int frameCount;
    f32 nx, nz, ny;
    f32 len, inv, dot;
    f32 fx, fy, fz, ff;
    f32 dx, dy, dz, k;
    int i;
    struct
    {
        s16 rot[3];
        f32 scale;
        f32 pos[3];
    } stk;

    if ((flags & 2) != 0)
    {
        if ((obj->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
        {
            Obj_FreeObject(obj);
        }
        obj->anim.alpha = 0;
    }
    else
    {
        setup = *(u8**)&obj->anim.placementData;
        if ((flags & 1) == 0)
        {
            if (((ObjAnimComponent*)obj)->bankIndex == 0)
            {
                triggerBit = mainGetBit(((DimbossicesmashPlacement*)setup)->triggerGameBit);
                if (triggerBit != 0 || ((DimbossicesmashPlacement*)setup)->triggerGameBit == -1)
                {
                    state[0x29e] = state[0x29e] | 1;
                    mainSetBits(((DimbossicesmashPlacement*)setup)->activateGameBit, 1);
                    lbl_803DDB00 = 1;
                }
            }
            else if (lbl_803DDB00 != 0)
            {
                state[0x29e] = flags | 1;
            }
            obj->anim.alpha = 0;
        }
        else
        {
            obj->anim.alpha = 0xff;
            cnt = (((DimBossIceSmashState*)state)->timer += framesThisStep);
            if (cnt >= ((DimbossicesmashPlacement*)setup)->lifetime)
            {
                state[0x29e] = state[0x29e] | 2;
            }
            frameCount = ((DimBossIceSmashState*)state)->timer;
            if (frameCount > ((DimbossicesmashPlacement*)setup)->fadeStartFrame &&
                (fadeDuration = ((DimbossicesmashPlacement*)setup)->lifetime - ((DimbossicesmashPlacement*)setup)->fadeStartFrame) != 0)
            {
                alphaVal = (int)(255.0f *
                    (1.0f -
                        (f32)(frameCount - ((DimbossicesmashPlacement*)setup)->fadeStartFrame) / (
                            f32)fadeDuration));
                if (alphaVal > 0xff)
                {
                    alphaVal = 0xff;
                }
                else if (alphaVal < 0)
                {
                    alphaVal = 0;
                }
                obj->anim.alpha = alphaVal;
            }
            obj->anim.velocityX = timeDelta * ((DimBossIceSmashState*)state)->accelX + obj
                ->anim.velocityX;
            obj->anim.velocityY = timeDelta * ((DimBossIceSmashState*)state)->accelY + obj
                ->anim.velocityY;
            obj->anim.velocityZ = timeDelta * ((DimBossIceSmashState*)state)->accelZ + obj
                ->anim.velocityZ;
            ((DimBossIceSmashState*)state)->angVelX =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelX + ((DimBossIceSmashState*)state)->angVelX;
            ((DimBossIceSmashState*)state)->angVelY =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelY + ((DimBossIceSmashState*)state)->angVelY;
            ((DimBossIceSmashState*)state)->angVelZ =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelZ + ((DimBossIceSmashState*)state)->angVelZ;
            if ((state[0x29f] & 1) != 0)
            {
                if (obj->anim.velocityX < 0.0f)
                {
                    obj->anim.velocityX = 0.0f;
                }
            }
            else if (obj->anim.velocityX > 0.0f)
            {
                obj->anim.velocityX = 0.0f;
            }
            if ((state[0x29f] & 2) != 0)
            {
                if (obj->anim.velocityZ < 0.0f)
                {
                    obj->anim.velocityZ = 0.0f;
                }
            }
            else if (obj->anim.velocityZ > 0.0f)
            {
                obj->anim.velocityZ = 0.0f;
            }
            if ((state[0x29f] & 4) != 0)
            {
                if (((DimBossIceSmashState*)state)->angVelX < 0.0f)
                {
                    ((DimBossIceSmashState*)state)->angVelX = 0.0f;
                }
            }
            else if (((DimBossIceSmashState*)state)->angVelX > 0.0f)
            {
                ((DimBossIceSmashState*)state)->angVelX = 0.0f;
            }
            if ((state[0x29f] & 8) != 0)
            {
                if (((DimBossIceSmashState*)state)->angVelY < 0.0f)
                {
                    ((DimBossIceSmashState*)state)->angVelY = 0.0f;
                }
            }
            else if (((DimBossIceSmashState*)state)->angVelY > 0.0f)
            {
                ((DimBossIceSmashState*)state)->angVelY = 0.0f;
            }
            if ((state[0x29f] & 0x10) != 0)
            {
                if (((DimBossIceSmashState*)state)->angVelZ < 0.0f)
                {
                    ((DimBossIceSmashState*)state)->angVelZ = 0.0f;
                }
            }
            else if (((DimBossIceSmashState*)state)->angVelZ > 0.0f)
            {
                ((DimBossIceSmashState*)state)->angVelZ = 0.0f;
            }
            obj->anim.localPosX = obj->anim.velocityX * timeDelta + obj->
                anim.localPosX;
            obj->anim.localPosY = obj->anim.velocityY * timeDelta + obj->
                anim.localPosY;
            obj->anim.localPosZ = obj->anim.velocityZ * timeDelta + obj->
                anim.localPosZ;
            obj->anim.rotX = ((DimBossIceSmashState*)state)->angVelX * timeDelta + (f32)obj
                ->anim.rotX;
            obj->anim.rotY = ((DimBossIceSmashState*)state)->angVelY * timeDelta + (f32)obj
                ->anim.rotY;
            obj->anim.rotZ = ((DimBossIceSmashState*)state)->angVelZ * timeDelta + (f32)obj
                ->anim.rotZ;
            if ((((DimbossicesmashPlacement*)setup)->flags & 2) != 0)
            {
                (*gPathControlInterface)->update(obj, state, timeDelta);
                (*gPathControlInterface)->apply(obj, state);
                (*gPathControlInterface)->advance(obj, state, timeDelta);
                if (((DimBossIceSmashState*)state)->homingEnabled != 0)
                {
                    nx = -obj->anim.velocityX;
                    ny = -obj->anim.velocityY;
                    nz = -obj->anim.velocityZ;
                    len = sqrtf(nz * nz + (nx * nx + ny * ny));
                    if (0.0f != len)
                    {
                        inv = 1.0f / len;
                        nx = nx * inv;
                        ny = ny * inv;
                        nz = nz * inv;
                    }
                    fx = ((DimBossIceSmashState*)state)->homingDirX;
                    fy = ((DimBossIceSmashState*)state)->homingDirY;
                    fz = ((DimBossIceSmashState*)state)->homingDirZ;
                    dot = 2.0f *
                        (nz * fz + (nx * fx + ny * fy));
                    obj->anim.velocityX = fx * dot;
                    obj->anim.velocityY = fy * dot;
                    obj->anim.velocityZ = fz * dot;
                    obj->anim.velocityX = obj->anim.velocityX - nx;
                    obj->anim.velocityY = obj->anim.velocityY - ny;
                    obj->anim.velocityZ = obj->anim.velocityZ - nz;
                    obj->anim.velocityY = obj->anim.velocityY * len;
                    obj->anim.velocityY *= 0.75f;
                    obj->anim.velocityX = obj->anim.velocityX * len;
                    obj->anim.velocityZ = obj->anim.velocityZ * len;
                    obj->anim.velocityX *= (ff = 0.9f);
                    obj->anim.velocityZ *= ff;
                }
            }
            if ((((DimbossicesmashPlacement*)setup)->flags & 4) != 0 && obj->anim.alpha == 0xff)
            {
                dx = obj->anim.localPosX - obj->anim.previousLocalPosX;
                dy = obj->anim.localPosY - obj->anim.previousLocalPosY;
                dz = obj->anim.localPosZ - obj->anim.previousLocalPosZ;
                i = 0;
                do
                {
                    k = i / 2.0f;
                    stk.pos[0] = dx * k + obj->anim.previousLocalPosX;
                    stk.pos[1] = dy * k + obj->anim.previousLocalPosY;
                    stk.pos[2] = dz * k + obj->anim.previousLocalPosZ;
                    (*gPartfxInterface)->spawnObject(obj, DIMBOSSICESMASH_PARTFX, &stk, 0x200001, -1, NULL);
                    i++;
                }
                while (i < 2);
            }
        }
    }
}

void DIMBossIceSmash_init(GameObject* obj, u8* params)
{
    u8* state;
    f32 fz;
    u8 initState;
    u8 buf[8];

    buf[0] = 5;
    ((ObjAnimComponent*)obj)->bankIndex = params[0x18];
    state = obj->extra;
    fz = 0.0f;
    ((DimBossIceSmashState*)state)->spawnScaleX = 0.0f;
    ((DimBossIceSmashState*)state)->spawnScaleY = fz;
    ((DimBossIceSmashState*)state)->spawnScaleZ = fz;
    dimbossicesmash_initLaunchState(obj, state, params);
    initState = (mainGetBit(((DimbossicesmashPlacement*)params)->activateGameBit) != 0) ? 2 : 0;
    state[0x29e] = initState;
    lbl_803DDB00 = 0;
    if ((((DimbossicesmashPlacement*)params)->flags & 2) != 0)
    {
        (*gPathControlInterface)->init(state, 0, 0x40002, 1);
        (*gPathControlInterface)->setup(state, 1, lbl_80322368, lbl_803DBDF8, buf);
        (*gPathControlInterface)->attachObject(obj, state);
    }
}

void DIMBossIceSmash_release(void)
{
}

void DIMBossIceSmash_initialise(void)
{
}

ObjectDescriptor10WithPadding gDIMBossIceSmashObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)DIMBossIceSmash_initialise,
        (ObjectDescriptorCallback)DIMBossIceSmash_release,
        0,
        (ObjectDescriptorCallback)DIMBossIceSmash_init,
        (ObjectDescriptorCallback)DIMBossIceSmash_update,
        (ObjectDescriptorCallback)DIMBossIceSmash_hitDetect,
        (ObjectDescriptorCallback)DIMBossIceSmash_render,
        (ObjectDescriptorCallback)DIMBossIceSmash_free,
        (ObjectDescriptorCallback)DIMBossIceSmash_getObjectTypeId,
        DIMBossIceSmash_getExtraSize,
    },
    0,
};
