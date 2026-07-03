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
 */
#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct KtlazerwallPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 intensityBit;    /* 0x1A: game bit; its value is the wall's intensity */
    s16 fireThreshold;   /* 0x1C: intensity at/above which the wall fires */
    s16 activeBit;       /* 0x1E: game bit set while the lightning arc is live */
} KtlazerwallPlacement;


/* overlays the object's extra block; the low flags byte lives at offset 0
   (pad0) and is accessed as a u8 array elsewhere. */
typedef struct KtlazerwallState
{
    u8 pad0[0x4 - 0x0];
    f32 reloadTimer;     /* 0x04: counts down between arc-snap sfx */
    f32 driftTimer;      /* 0x08: render-side bolt reposition timer */
    f32 driftSpeed;      /* 0x0C: signed bolt drift speed */
    s32 bolt;            /* 0x10: lightning bolt allocation (pointer) */
} KtlazerwallState;

int ktlazerwall_getExtraSize(void) { return 0x14; }

int ktlazerwall_getObjectTypeId(void) { return 0x0; }

void ktlazerwall_hitDetect(void)
{
}

void ktlazerwall_initialise(void)
{
}

void ktlazerwall_release(void)
{
}

void ktlazerwall_free(int obj)
{
    char* extra = ((GameObject*)obj)->extra;
    void* bolt = *(void**)&((KtlazerwallState*)extra)->bolt;
    if (bolt != 0)
    {
        mm_free(bolt);
        *(void**)&((KtlazerwallState*)extra)->bolt = 0;
    }
}

void ktlazerwall_init(int obj, char* placement)
{
    char* extra = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)placement[0x18] << 8);
    ((KtlazerwallState*)extra)->reloadTimer = lbl_803E6898;
    ((KtlazerwallState*)extra)->driftSpeed = lbl_803E68BC * (f32)(int)randomGetRange(0x50, 0x78);
    if ((s32)randomGetRange(0, 1) != 0)
    {
        ((KtlazerwallState*)extra)->driftSpeed = -((KtlazerwallState*)extra)->driftSpeed;
    }
}

void ktlazerwall_update(int obj)
{
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    u8* flags = ((GameObject*)obj)->extra;
    int intensity;
    int mode;
    int i;
    flags[1] = flags[0];
    flags[0] &= ~3;
    intensity = (s16)GameBit_Get(((KtlazerwallPlacement*)placement)->intensityBit);
    if (intensity >= ((KtlazerwallPlacement*)placement)->fireThreshold)
    {
        flags[0] |= 4;
    }
    else
    {
        flags[0] &= ~4;
        if (GameBit_Get(((KtlazerwallPlacement*)placement)->activeBit) == 0)
        {
            return;
        }
    }
    ((GameObject*)obj)->anim.rotZ += 910;
    if (intensity >= 15 && (flags[0] & 9) == 0)
    {
        GameBit_Set(((KtlazerwallPlacement*)placement)->activeBit, 1);
        flags[0] |= 9;
        ktrexfloorswitch_spawnEnergyArc(obj, lbl_803E68B8, 120);
        (*gPartfxInterface)->spawnObject((void*)obj, 1150, NULL, 2, -1, NULL);
        for (i = 10; i != 0; i--)
        {
            mode = 2;
            (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        }
        ((KtlazerwallState*)flags)->reloadTimer = (f32)(int)randomGetRange(1, 60);
    }
    if (flags[0] & 4)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 1;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        if ((flags[1] & 4) == 0)
        {
            Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap3);
        }
    }
    if (flags[0] & 8)
    {
        mode = 0;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
        mode = 2;
        (*gPartfxInterface)->spawnObject((void*)obj, 1164, NULL, 2, -1, &mode);
    }
    if ((flags[0] & 8) == 0 && (flags[1] & 8) != 0)
    {
        Sfx_PlayFromObject(obj, SFXmv_blkhit_c);
    }
    {
        f32 timer = ((KtlazerwallState*)flags)->reloadTimer;
        f32 limit = lbl_803E6898;
        if (timer > limit)
        {
            ((KtlazerwallState*)flags)->reloadTimer = timer - timeDelta;
            if (((KtlazerwallState*)flags)->reloadTimer <= limit)
            {
                Sfx_PlayFromObject(obj, SFXmv_bflconc1);
                ((KtlazerwallState*)flags)->reloadTimer = lbl_803E6898;
            }
        }
    }
}

void ktlazerwall_render(int obj)
{
    char* extra = ((GameObject*)obj)->extra;
    int placement = *(int*)&((GameObject*)obj)->anim.placementData;
    int bolt;
    if (*(void**)&((KtlazerwallState*)extra)->bolt != 0)
    {
        ((KtlazerwallState*)extra)->driftTimer -= timeDelta;
        if (((KtlazerwallState*)extra)->driftTimer <= lbl_803E6898)
        {
            f32 kick = lbl_803E68B0 * ((KtlazerwallState*)extra)->driftSpeed;
            bolt = ((KtlazerwallState*)extra)->bolt;
            *(f32*)(bolt + 0x10) -= kick * lbl_803E68B4;
            ((KtlazerwallState*)extra)->driftTimer = (f32)(int)randomGetRange(0xa, 0x78);
        }
        else
        {
            bolt = ((KtlazerwallState*)extra)->bolt;
            *(f32*)(bolt + 0x10) += ((KtlazerwallState*)extra)->driftSpeed * timeDelta;
        }
        lightningRender(*(void**)&((KtlazerwallState*)extra)->bolt);
        *(u16*)(((KtlazerwallState*)extra)->bolt + 0x20) += framesThisStep;
        bolt = ((KtlazerwallState*)extra)->bolt;
        if (*(u16*)(bolt + 0x20) >= *(u16*)(bolt + 0x22))
        {
            mm_free((void*)bolt);
            ((KtlazerwallState*)extra)->bolt = 0;
            *(u8*)extra &= ~8;
            GameBit_Set(((KtlazerwallPlacement*)placement)->activeBit, 0);
        }
    }
}
