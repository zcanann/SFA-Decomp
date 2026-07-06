/* DLL 0x13E — DIMBossIceSmash [0x80194890-0x80197190): spinning ice shards
 * launched during the DIM boss fight.  Each shard integrates velocity and
 * rotation, optionally follows a path-control surface bounce, fades over a
 * per-setup lifetime window, and emits two trail particles per frame while
 * fully opaque. */
#include "main/game_object.h"
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/gamebits.h"

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

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 sqrtf(f32);
extern void Obj_FreeObject(u8* obj);
extern u8 lbl_803DDB00;
extern u8 lbl_80322368[0xC];
extern u8 lbl_803DBDF8[8];

/* seed the icesmash launch state from the setup record: spawn position/rotation,
 * launch velocity (optionally homing on the target point), rotation velocities
 * and the gravity/clamp direction flags. */
void fn_80196520(u8* obj, u8* state, u8* setup)
{
    f32 vx, vy, vz;
    f32 spd, len;

    ((GameObject*)obj)->anim.localPosX = ((DimBossIceSmashState*)state)->spawnScaleX * ((GameObject*)obj)->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posX;
    ((GameObject*)obj)->anim.localPosY = ((DimBossIceSmashState*)state)->spawnScaleY * ((GameObject*)obj)->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posY;
    ((GameObject*)obj)->anim.localPosZ = ((DimBossIceSmashState*)state)->spawnScaleZ * ((GameObject*)obj)->anim.
        rootMotionScale + ((ObjPlacement*)setup)->posZ;
    ((GameObject*)obj)->anim.rotX = ((DimbossicesmashPlacement*)setup)->spawnRotX;
    ((GameObject*)obj)->anim.rotY = ((DimbossicesmashPlacement*)setup)->spawnRotY;
    ((GameObject*)obj)->anim.rotZ = ((DimbossicesmashPlacement*)setup)->spawnRotZ;
    if ((((DimbossicesmashPlacement*)setup)->flags & 1) != 0)
    {
        spd = (f32) * (s16*)(setup + 0x20) / 100.0f;
        vx = ((GameObject*)obj)->anim.localPosX - (f32) * (s16*)(setup + 0x42);
        vy = ((GameObject*)obj)->anim.localPosY - (f32) * (s16*)(setup + 0x44);
        vz = ((GameObject*)obj)->anim.localPosZ - (f32) * (s16*)(setup + 0x46);
        len = sqrtf(vz * vz + (vx * vx + vy * vy));
        if (0.0f != len)
        {
            vx = vx / len;
            vy = vy / len;
            vz = vz / len;
        }
        ((GameObject*)obj)->anim.velocityX = spd * vx;
        ((GameObject*)obj)->anim.velocityY = spd * vy;
        ((GameObject*)obj)->anim.velocityZ = spd * vz;
    }
    else
    {
        ((GameObject*)obj)->anim.velocityX = (f32) * (s16*)(setup + 0x20) / 100.0f;
        ((GameObject*)obj)->anim.velocityY = (f32) * (s16*)(setup + 0x22) / 100.0f;
        ((GameObject*)obj)->anim.velocityZ = (f32) * (s16*)(setup + 0x24) / 100.0f;
    }
    ((DimBossIceSmashState*)state)->angVelX = (f32) * (s16*)(setup + 0x2c);
    ((DimBossIceSmashState*)state)->angVelY = (f32) * (s16*)(setup + 0x2e);
    ((DimBossIceSmashState*)state)->angVelZ = (f32) * (s16*)(setup + 0x30);
    if (((GameObject*)obj)->anim.velocityX > 0.0f)
    {
        state[0x29f] = state[0x29f] | 1;
    }
    if (((GameObject*)obj)->anim.velocityZ > 0.0f)
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
    ((DimBossIceSmashState*)state)->angAccelX = (f32) * (s16*)(setup + 0x32) / 10.0f;
    ((DimBossIceSmashState*)state)->angAccelY = (f32) * (s16*)(setup + 0x34) / 10.0f;
    ((DimBossIceSmashState*)state)->angAccelZ = (f32) * (s16*)(setup + 0x36) / 10.0f;
    ((DimBossIceSmashState*)state)->accelX = (f32) * (s16*)(setup + 0x26) / 1000.0f;
    ((DimBossIceSmashState*)state)->accelY = (f32) * (s16*)(setup + 0x28) / 1000.0f;
    ((DimBossIceSmashState*)state)->accelZ = (f32) * (s16*)(setup + 0x2a) / 1000.0f;
    ((DimBossIceSmashState*)state)->timer = 0;
}

int dimbossicesmash_getExtraSize(void) { return 0x2a0; }

u32 dimbossicesmash_getObjectTypeId(int* obj) { return (*((u8*)((GameObject*)obj)->anim.placementData + 0x18) << 11) | 0x400; }

void dimbossicesmash_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void dimbossicesmash_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void dimbossicesmash_hitDetect(void)
{
}

/* gate on the trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */
void dimbossicesmash_update(u8* obj)
{
    u8* state = ((GameObject*)obj)->extra;
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
        if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
        {
            Obj_FreeObject(obj);
        }
        ((GameObject*)obj)->anim.alpha = 0;
    }
    else
    {
        setup = *(u8**)&((GameObject*)obj)->anim.placementData;
        if ((flags & 1) == 0)
        {
            if (((ObjAnimComponent*)obj)->bankIndex == 0)
            {
                triggerBit = GameBit_Get(((DimbossicesmashPlacement*)setup)->triggerGameBit);
                if (triggerBit != 0 || ((DimbossicesmashPlacement*)setup)->triggerGameBit == -1)
                {
                    state[0x29e] = state[0x29e] | 1;
                    GameBit_Set(((DimbossicesmashPlacement*)setup)->activateGameBit, 1);
                    lbl_803DDB00 = 1;
                }
            }
            else if (lbl_803DDB00 != 0)
            {
                state[0x29e] = flags | 1;
            }
            ((GameObject*)obj)->anim.alpha = 0;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = 0xff;
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
                ((GameObject*)obj)->anim.alpha = alphaVal;
            }
            ((GameObject*)obj)->anim.velocityX = timeDelta * ((DimBossIceSmashState*)state)->accelX + ((GameObject*)obj)
                ->anim.velocityX;
            ((GameObject*)obj)->anim.velocityY = timeDelta * ((DimBossIceSmashState*)state)->accelY + ((GameObject*)obj)
                ->anim.velocityY;
            ((GameObject*)obj)->anim.velocityZ = timeDelta * ((DimBossIceSmashState*)state)->accelZ + ((GameObject*)obj)
                ->anim.velocityZ;
            ((DimBossIceSmashState*)state)->angVelX =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelX + ((DimBossIceSmashState*)state)->angVelX;
            ((DimBossIceSmashState*)state)->angVelY =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelY + ((DimBossIceSmashState*)state)->angVelY;
            ((DimBossIceSmashState*)state)->angVelZ =
                timeDelta * ((DimBossIceSmashState*)state)->angAccelZ + ((DimBossIceSmashState*)state)->angVelZ;
            if ((state[0x29f] & 1) != 0)
            {
                if (((GameObject*)obj)->anim.velocityX < 0.0f)
                {
                    ((GameObject*)obj)->anim.velocityX = 0.0f;
                }
            }
            else if (((GameObject*)obj)->anim.velocityX > 0.0f)
            {
                ((GameObject*)obj)->anim.velocityX = 0.0f;
            }
            if ((state[0x29f] & 2) != 0)
            {
                if (((GameObject*)obj)->anim.velocityZ < 0.0f)
                {
                    ((GameObject*)obj)->anim.velocityZ = 0.0f;
                }
            }
            else if (((GameObject*)obj)->anim.velocityZ > 0.0f)
            {
                ((GameObject*)obj)->anim.velocityZ = 0.0f;
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
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->
                anim.localPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->
                anim.localPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->
                anim.localPosZ;
            ((GameObject*)obj)->anim.rotX = ((DimBossIceSmashState*)state)->angVelX * timeDelta + (f32)((GameObject*)obj)
                ->anim.rotX;
            ((GameObject*)obj)->anim.rotY = ((DimBossIceSmashState*)state)->angVelY * timeDelta + (f32)((GameObject*)obj)
                ->anim.rotY;
            ((GameObject*)obj)->anim.rotZ = ((DimBossIceSmashState*)state)->angVelZ * timeDelta + (f32)((GameObject*)obj)
                ->anim.rotZ;
            if ((((DimbossicesmashPlacement*)setup)->flags & 2) != 0)
            {
                (*gPathControlInterface)->update(obj, state, timeDelta);
                (*gPathControlInterface)->apply(obj, state);
                (*gPathControlInterface)->advance(obj, state, timeDelta);
                if (((DimBossIceSmashState*)state)->homingEnabled != 0)
                {
                    nx = -((GameObject*)obj)->anim.velocityX;
                    ny = -((GameObject*)obj)->anim.velocityY;
                    nz = -((GameObject*)obj)->anim.velocityZ;
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
                    ((GameObject*)obj)->anim.velocityX = fx * dot;
                    ((GameObject*)obj)->anim.velocityY = fy * dot;
                    ((GameObject*)obj)->anim.velocityZ = fz * dot;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX - nx;
                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY - ny;
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ - nz;
                    ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * len;
                    ((GameObject*)obj)->anim.velocityY *= 0.75f;
                    ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * len;
                    ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * len;
                    ((GameObject*)obj)->anim.velocityX *= (ff = 0.9f);
                    ((GameObject*)obj)->anim.velocityZ *= ff;
                }
            }
            if ((((DimbossicesmashPlacement*)setup)->flags & 4) != 0 && ((GameObject*)obj)->anim.alpha == 0xff)
            {
                dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX;
                dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)obj)->anim.previousLocalPosY;
                dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ;
                i = 0;
                do
                {
                    k = i / 2.0f;
                    stk.pos[0] = dx * k + ((GameObject*)obj)->anim.previousLocalPosX;
                    stk.pos[1] = dy * k + ((GameObject*)obj)->anim.previousLocalPosY;
                    stk.pos[2] = dz * k + ((GameObject*)obj)->anim.previousLocalPosZ;
                    (*gPartfxInterface)->spawnObject(obj, 1000, &stk, 0x200001, -1, NULL);
                    i++;
                }
                while (i < 2);
            }
        }
    }
}

void dimbossicesmash_init(GameObject* obj, u8* params)
{
    u8* state;
    f32 fz;
    u8 t;
    u8 buf[8];

    buf[0] = 5;
    ((ObjAnimComponent*)obj)->bankIndex = params[0x18];
    state = ((GameObject*)obj)->extra;
    fz = 0.0f;
    ((DimBossIceSmashState*)state)->spawnScaleX = 0.0f;
    ((DimBossIceSmashState*)state)->spawnScaleY = fz;
    ((DimBossIceSmashState*)state)->spawnScaleZ = fz;
    fn_80196520((u8*)obj, state, params);
    t = (GameBit_Get(((DimbossicesmashPlacement*)params)->activateGameBit) != 0) ? 2 : 0;
    state[0x29e] = t;
    lbl_803DDB00 = 0;
    if ((((DimbossicesmashPlacement*)params)->flags & 2) != 0)
    {
        (*gPathControlInterface)->init(state, 0, 0x40002, 1);
        (*gPathControlInterface)->setup(state, 1, lbl_80322368, lbl_803DBDF8, buf);
        (*gPathControlInterface)->attachObject(obj, state);
    }
}

void dimbossicesmash_release(void)
{
}

void dimbossicesmash_initialise(void)
{
}
