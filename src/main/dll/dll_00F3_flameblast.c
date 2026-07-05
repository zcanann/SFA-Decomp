/*
 * flameblast (DLL 0xF3) - Tricky's fire-breath projectile, a member of
 * the pushable/transporter object family.
 *
 * Spawned by Tricky (getTrickyObject), the blast flies along the rotated
 * fire direction: fn_8017805C seeds the velocity from Tricky's heading and
 * the path/queued-particle origin, and flameblast_update integrates the
 * launch position over a per-frame timer while arming the damage hit
 * volume once the timer passes a threshold. The object frees itself when
 * Tricky is gone or its free flag (state.freeRequested) is set.
 */
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/vecrotatezxyarg_struct.h"

#define FLAMEBLAST_OBJFLAG_RENDERED 0x800

typedef struct FlameblastState
{
    f32 timer;         /* 0x00: per-frame flight timer */
    f32 launchPosX;    /* 0x04: launch origin used by the localPos integration */
    f32 launchPosY;    /* 0x08 */
    f32 launchPosZ;    /* 0x0C */
    u8 freeRequested;  /* 0x10: set externally to free the object next tick */
    u8 hitVolumeDelay; /* 0x11: frames to delay before clearing hit volumes */
    u8 pad12[0x14 - 0x12];
} FlameblastState;

STATIC_ASSERT(offsetof(FlameblastState, freeRequested) == 0x10);
STATIC_ASSERT(offsetof(FlameblastState, hitVolumeDelay) == 0x11);
STATIC_ASSERT(sizeof(FlameblastState) == 0x14);

typedef struct FlameblastPlacement
{
    u8 pad0[0x1a - 0x0];
    s16 initialTimer; /* 0x1a: seeds the flight timer (scaled at init) */
} FlameblastPlacement;

extern void Obj_FreeObject(int obj);
extern void fn_80098B18(int obj, f32 f, int a, int b, int c, int d);
int fn_8017805C(GameObject* obj, FlameblastState* state);
extern void vecRotateZXY(void* in, void* out);
extern int fn_80138F90(void);
extern f32* trickyGetQueuedPathParticlePos(s16* tricky);
extern f32 timeDelta;

void objSetAnimSpeedTo1(GameObject* obj)
{
    ((FlameblastState*)obj->extra)->freeRequested = 1;
}

int fn_8017805C(GameObject* obj, FlameblastState* state)
{
    s16* tricky = getTrickyObject();
    f32* origin;
    f32 reach = 0.4f;
    VecRotateZXYArg vec;

    if (state->freeRequested != 0 || tricky == NULL)
    {
        Obj_FreeObject((int)obj);
        return 0;
    }
    obj->anim.velocityX = 0.0f;
    obj->anim.velocityY = 0.0f;
    obj->anim.velocityZ = -1.5f;
    vec.pos[1] = 0.0f;
    vec.pos[2] = 0.0f;
    vec.pos[3] = 0.0f;
    vec.pos[0] = 1.0f;
    vec.dir[2] = tricky[2];
    vec.dir[1] = tricky[1];
    vec.dir[0] = tricky[0] + fn_80138F90();
    vecRotateZXY(&vec, &obj->anim.velocityX);
    if ((((GameObject*)tricky)->objectFlags & FLAMEBLAST_OBJFLAG_RENDERED) != 0)
    {
        origin = trickyGetQueuedPathParticlePos(tricky);
    }
    else
    {
        origin = &((GameObject*)tricky)->anim.localPosX;
    }
    state->launchPosX = -(reach * obj->anim.velocityX - origin[0]);
    state->launchPosY = -(reach * obj->anim.velocityY - origin[1]);
    state->launchPosZ = -(reach * obj->anim.velocityZ - origin[2]);
    if (state->hitVolumeDelay != 0)
    {
        state->hitVolumeDelay -= 1;
    }
    else
    {
        ObjHits_ClearHitVolumes((int)obj);
    }
    return 1;
}

int flameblast_getExtraSize(void)
{
    return sizeof(FlameblastState);
}

void flameblast_render(GameObject* obj)
{
    f32 color[3];
    f32 scale = 0.033333335f * ((FlameblastState*)obj->extra)->timer + 0.2f;
    color[0] = 0.0f;
    color[1] = 1.0f;
    color[2] = 0.0f;
    fn_80098B18((int)obj, scale, 2, 0, 0, (int)color);
}

void flameblast_update(GameObject* obj)
{
    FlameblastState* state = obj->extra;
    state->timer = state->timer + timeDelta;
    if (state->timer > 24.0f)
    {
        state->timer = state->timer - 24.0f;
        if (fn_8017805C(obj, state) == 0)
        {
            return;
        }
    }
    else
    {
        if (state->timer > 6.0f)
        {
            if (state->hitVolumeDelay == 0)
            {
                ObjHits_SetHitVolumeSlot((u32)obj, 0x1a, 1, 0);
            }
        }
    }
    obj->anim.localPosX = obj->anim.velocityX * state->timer + state->launchPosX;
    obj->anim.localPosY = obj->anim.velocityY * state->timer + state->launchPosY;
    obj->anim.localPosZ = obj->anim.velocityZ * state->timer + state->launchPosZ;
}

void flameblast_init(GameObject* obj, FlameblastPlacement* def)
{
    FlameblastState* state = obj->extra;
    fn_8017805C(obj, state);
    state->timer = 3.4285715f * (f32)def->initialTimer;
    state->hitVolumeDelay = 2;
}
