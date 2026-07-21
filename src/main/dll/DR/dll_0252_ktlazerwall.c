/*
 * ktlazerwall (DLL 0x252) - a SharpClaw laser fence/wall whose intensity
 * is driven by a placement game bit (see ktlazerlight, DLL 0x253, for the
 * point light it pairs with).
 *
 * Each tick a status game bit's value is compared against a threshold to
 * decide whether the wall is "firing". On the rising edge it sets its
 * active game bit, spawns an energy arc plus particle bursts, and seeds a
 * lightning bolt that the render pass animates (drifting its position and
 * advancing its lifetime) until it expires. A flags byte at extra[0]
 * tracks the firing/lightning state, with extra[1] holding the previous
 * frame's flags so sfx fire on edges.
 *
 * ktrexfloorswitch_spawnEnergyArc is invoked with THIS object (its
 * 'runtime' overlays KtlazerwallState, where 0x10 is the bolt pointer -
 * distinct from ktrexfloorswitch's flags byte at the same offset).
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/DR/dll_0251_ktrexfloorswitch.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/newclouds.h"
#include "main/game_object.h"
#include "main/vecmath.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DR/dll_0252_ktlazerwall.h"

const union KtlazerwallConstF32 lbl_803E6898 = {0.0f};
const union KtlazerwallConstF32 lbl_803E689C = {0.5f};
const union KtlazerwallConstF32 lbl_803E68A0 = {0.1f};
const union KtlazerwallConstF32 lbl_803E68A4 = {0.3f};

void ktrexfloorswitch_spawnEnergyArc(GameObject* obj, f32 scale, int angle)
{
    KtlazerwallState* state = obj->extra;
    Vec3f pos;
    Vec3f dir;
    if (state->bolt != NULL)
    {
        mm_free(state->bolt);
        state->bolt = NULL;
    }
    pos.x = obj->anim.localPosX;
    pos.y = obj->anim.localPosY;
    pos.z = obj->anim.localPosZ;
    dir.x = lbl_803E6898.f;
    {
        f32 fr = angle;
        fr = fr * state->driftSpeed;
        dir.y = -(fr * lbl_803E689C.f);
    }
    dir.z = scale;
    vecRotateZXY(&obj->anim.rotX, &dir.x);
    dir.x += obj->anim.localPosX;
    dir.y += obj->anim.localPosY;
    dir.z += obj->anim.localPosZ;
    state->driftTimer = (f32)(int)randomGetRange(10, angle);
    state->bolt = lightningCreate(&pos, &dir, lbl_803E68A0.f, lbl_803E68A4.f, angle, 96, 0);
}

const union KtlazerwallConstF32 lbl_803E68B0 = {120.0f};
const union KtlazerwallConstF32 lbl_803E68B4 = {0.25f};
const union KtlazerwallConstF32 lbl_803E68B8 = {230.0f};
const union KtlazerwallConstF32 lbl_803E68BC = {0.01f};

int KT_Lazerwall_getExtraSize(void)
{
    return sizeof(KtlazerwallState);
}

int KT_Lazerwall_getObjectTypeId(void)
{
    return 0x0;
}

void KT_Lazerwall_free(GameObject* obj)
{
    KtlazerwallState* state = obj->extra;
    LightningEffect* bolt = state->bolt;
    if (bolt != NULL)
    {
        mm_free(bolt);
        state->bolt = NULL;
    }
}

void KT_Lazerwall_render(GameObject* obj)
{
    KtlazerwallState* state = obj->extra;
    KtlazerwallPlacement* placement = (KtlazerwallPlacement*)obj->anim.placementData;
    LightningEffect* bolt;
    if (state->bolt != NULL)
    {
        state->driftTimer -= timeDelta;
        if (state->driftTimer <= lbl_803E6898.f)
        {
            f32 kick = lbl_803E68B0.f * state->driftSpeed;
            bolt = state->bolt;
            bolt->end[1] -= kick * lbl_803E68B4.f;
            state->driftTimer = (f32)(int)randomGetRange(0xa, 0x78);
        }
        else
        {
            bolt = state->bolt;
            bolt->end[1] += state->driftSpeed * timeDelta;
        }
        lightningRender(state->bolt);
        state->bolt->timer += framesThisStep;
        bolt = state->bolt;
        if (bolt->timer >= bolt->lifetime)
        {
            mm_free(bolt);
            state->bolt = NULL;
            state->flags &= ~KT_LAZERWALL_FLAG_BOLT_ACTIVE;
            mainSetBits(placement->activeBit, 0);
        }
    }
}

void KT_Lazerwall_hitDetect(void)
{
}

void KT_Lazerwall_update(GameObject* obj)
{
    KtlazerwallPlacement* placement = (KtlazerwallPlacement*)obj->anim.placementData;
    KtlazerwallState* state = obj->extra;
    int intensity;
    int mode;
    int i;
    state->previousFlags = state->flags;
    state->flags &= ~(KT_LAZERWALL_FLAG_TRIGGERED | 0x2);
    intensity = (s16)mainGetBit(placement->intensityBit);
    if (intensity >= placement->fireThreshold)
    {
        state->flags |= KT_LAZERWALL_FLAG_FIRING;
    }
    else
    {
        state->flags &= ~KT_LAZERWALL_FLAG_FIRING;
        if (mainGetBit(placement->activeBit) == 0)
        {
            return;
        }
    }
    obj->anim.rotZ += 910;
    if (intensity >= 15 &&
        (state->flags & (KT_LAZERWALL_FLAG_TRIGGERED | KT_LAZERWALL_FLAG_BOLT_ACTIVE)) == 0)
    {
        mainSetBits(placement->activeBit, 1);
        state->flags |= KT_LAZERWALL_FLAG_TRIGGERED | KT_LAZERWALL_FLAG_BOLT_ACTIVE;
        ktrexfloorswitch_spawnEnergyArc(obj, lbl_803E68B8.f, 120);
        (*gPartfxInterface)->spawnObject((void*)obj, 1150, NULL, 2, -1, NULL);
        for (i = 10; i != 0; i--)
        {
            mode = 2;
            (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        }
        state->reloadTimer = (f32)(int)randomGetRange(1, 60);
    }
    if (state->flags & KT_LAZERWALL_FLAG_FIRING)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 1;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        if ((state->previousFlags & KT_LAZERWALL_FLAG_FIRING) == 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wp_beamhit16);
        }
    }
    if (state->flags & KT_LAZERWALL_FLAG_BOLT_ACTIVE)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
    }
    if ((state->flags & KT_LAZERWALL_FLAG_BOLT_ACTIVE) == 0 &&
        (state->previousFlags & KT_LAZERWALL_FLAG_BOLT_ACTIVE) != 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_beamgenlp16);
    }
    {
        f32 limit;
        f32 timer = state->reloadTimer;
        limit = lbl_803E6898.f;
        if (timer > limit)
        {
            state->reloadTimer = timer - timeDelta;
            if (state->reloadTimer <= limit)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_blaserflyby16);
                state->reloadTimer = lbl_803E6898.f;
            }
        }
    }
}

void KT_Lazerwall_init(GameObject* obj, KtlazerwallPlacement* placement)
{
    KtlazerwallState* state = obj->extra;
    obj->anim.rotX = (s16)((s8)placement->rotX << 8);
    state->reloadTimer = lbl_803E6898.f;
    state->driftSpeed = lbl_803E68BC.f * (f32)(int)randomGetRange(0x50, 0x78);
    if ((s32)randomGetRange(0, 1) != 0)
    {
        state->driftSpeed = -state->driftSpeed;
    }
}

void KT_Lazerwall_release(void)
{
}

void KT_Lazerwall_initialise(void)
{
}
