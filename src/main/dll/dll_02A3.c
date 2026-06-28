/*
 * dll_02A3 - a short-lived spinning debris/particle object.
 *
 * On init it fades in from alpha 0, picks a random starting orientation
 * and random per-axis spin speeds. Each frame it fades the alpha up to a
 * cap, advances its rotation by the spin speeds, and drifts along its
 * velocity (gravity/launch supplied by fn_8023137C). It self-frees once
 * its lifetime decays past a threshold.
 *
 * lbl_803DDD90 is a live-instance refcount (bumped on init, dropped on
 * free); lbl_803DDD94 is a once-per-frame "an instance updated" flag,
 * cleared by hitDetect and set by the first update.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

typedef struct Dll2A3State
{
    f32 lifetime;
    s16 rotXSpeed;
    s16 rotYSpeed;
    s16 rotZSpeed;
    u8 pad0A[2];
} Dll2A3State;

STATIC_ASSERT(sizeof(Dll2A3State) == 0x0c);
STATIC_ASSERT(offsetof(Dll2A3State, rotXSpeed) == 0x04);
STATIC_ASSERT(offsetof(Dll2A3State, rotYSpeed) == 0x06);
STATIC_ASSERT(offsetof(Dll2A3State, rotZSpeed) == 0x08);

int dll_2A3_getExtraSize_ret_12(void) { return sizeof(Dll2A3State); }

int dll_2A3_getObjectTypeId(void) { return 0x0; }

void dll_2A3_release_nop(void)
{
}

void dll_2A3_initialise_nop(void)
{
}

void dll_2A3_free(void) { lbl_803DDD90 = lbl_803DDD90 - 1; }

void dll_2A3_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7118);
}

void dll_2A3_hitDetect(void) { lbl_803DDD94 = 0; }

void dll_2A3_update(int obj)
{
    f32 lifetimeFloor;
    f32 lifetime;
    f32 alpha;
    Dll2A3State* state = ((GameObject*)obj)->extra;

    if ((lifetime = state->lifetime) > (lifetimeFloor = lbl_803E711C))
    {
        state->lifetime = lifetime - timeDelta;
        if (state->lifetime <= lifetimeFloor)
        {
            state->lifetime = lifetimeFloor;
            Obj_FreeObject(obj);
            return;
        }
    }

    alpha = (f32)(u32)((GameObject*)obj)->anim.alpha;
    alpha = lbl_803E7120 * timeDelta + alpha;
    if (alpha > lbl_803E7124)
    {
        alpha = lbl_803E7124;
    }
    ((GameObject*)obj)->anim.alpha = alpha;

    ((GameObject*)obj)->anim.rotX = (s16)((f32)state->rotXSpeed * timeDelta + (f32) * (s16*)(obj + 0));
    ((GameObject*)obj)->anim.rotY = (s16)((f32)state->rotYSpeed * timeDelta + (f32) * (s16*)(obj + 2));
    ((GameObject*)obj)->anim.rotZ = (s16)((f32)state->rotZSpeed * timeDelta + (f32) * (s16*)(obj + 4));

    objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
            ((GameObject*)obj)->anim.velocityZ * timeDelta);

    if (lbl_803DDD94 == 0)
    {
        lbl_803DDD94 = 1;
    }
}

void dll_2A3_init(int obj)
{
    Dll2A3State* state = ((GameObject*)obj)->extra;

    ((GameObject*)obj)->anim.alpha = 0;
    ((GameObject*)obj)->anim.rotX = randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.rotY = randomGetRange(0, 0xffff);
    ((GameObject*)obj)->anim.rotZ = randomGetRange(0, 0xffff);
    state->rotXSpeed = randomGetRange(-0x32, 0x32);
    state->rotYSpeed = randomGetRange(-0x32, 0x32);
    state->rotZSpeed = randomGetRange(-0x32, 0x32);
    lbl_803DDD90 = lbl_803DDD90 + 1;
}

void fn_8023137C(int obj, f32* velocity)
{
    ((GameObject*)obj)->anim.velocityX = velocity[0];
    ((GameObject*)obj)->anim.velocityY = velocity[1];
    ((GameObject*)obj)->anim.velocityZ = velocity[2];
}

void fn_8023134C(int obj, int lifetime)
{
    Dll2A3State* state = ((GameObject*)obj)->extra;
    state->lifetime = lifetime;
}
