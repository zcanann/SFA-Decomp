/* DLL 0x1DD - DIM2 Icicle: a swaying ceiling icicle that detects a hit,
 * waits, then drops to its target Y floor position and triggers a game-bit. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* DIM2PathGenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#include "main/dll/waterfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/DIM/dll_01DD_dim2icicle.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/track_dolphin_api.h"

#define DIM2ICICLE_OBJFLAG_HITDETECT_DISABLED 0x2000

/* Dim2IcicleState.mode (offset 6) drop-sequence phase */
#define DIM2ICICLE_MODE_WAIT_HIT 0 /* hanging; wait for a hit */
#define DIM2ICICLE_MODE_DROP     1 /* falling toward the located drop-target Y */
#define DIM2ICICLE_MODE_IMPACTED 2 /* landed; fade out then reset (also set at init if already dropped) */
#define DIM2ICICLE_MODE_WOBBLE   3 /* post-hit sway before releasing */

typedef struct Dim2iciclePlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 resetPosY;
    u8 pad10[0x18 - 0x10];
    s8 initialRotX;
    u8 pad19[0x1E - 0x19];
    s16 impactGameBit;
} Dim2iciclePlacement;

int dim2icicle_getExtraSize(void) { return 0xc; }

int dim2icicle_getObjectTypeId(void) { return 0x0; }

void dim2icicle_free(void)
{
}

void dim2icicle_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dim2icicle_hitDetect(void)
{
}

void dim2icicle_update(GameObject *obj)
{
    ObjHitsPriorityState* hitState;
    Dim2IcicleState* icicle;
    Dim2iciclePlacement* placement;
    placement = (Dim2iciclePlacement*)obj->anim.placementData;
    icicle = (Dim2IcicleState*)obj->extra;
    switch (icicle->mode)
    {
    case DIM2ICICLE_MODE_WAIT_HIT:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0xe)
        {
            break;
        }
        icicle->wobbleRotY = randomGetRange(0x320, 0x4b0);
        icicle->mode = DIM2ICICLE_MODE_WOBBLE;
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        hitState->flags &= ~1;
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_sbalhis6);
        break;
    case DIM2ICICLE_MODE_WOBBLE:
    {
        f32 wobble;

        obj->anim.rotY = icicle->wobbleRotY;
        wobble = (f32)icicle->wobbleRotY;
        wobble *= 0.333f;
        icicle->wobbleRotY = wobble;
        if ((obj)->anim.rotY >= 10)
        {
            break;
        }
        obj->anim.rotY = 0;
        icicle->mode = DIM2ICICLE_MODE_DROP;
        icicle->timer = 0x3c;
        break;
    }
    case DIM2ICICLE_MODE_DROP:
        if (icicle->dropTargetFound == 0)
        {
            int hitCount;
            int i;
            TrackGroundHit** list;
            hitCount = hitDetectFn_80065e50(obj, (obj)->anim.localPosX, (obj)->anim.localPosY,
                                            (obj)->anim.localPosZ, &list, 0, 0);
            icicle->dropY = -100000.0f;
            for (i = 0; i < hitCount; i++)
            {
                TrackGroundHit* hit = list[i];
                if ((s8)hit->surfaceType == 0xe)
                {
                    icicle->dropY = hit->height;
                    i = hitCount;
                }
            }
            if (-100000.0f != icicle->dropY)
            {
                icicle->dropTargetFound = 1;
            }
        }
        if (icicle->timer > 0)
        {
            icicle->timer -= framesThisStep;
            if (icicle->timer <= 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_swdwood16);
            }
        }
        (obj)->anim.velocityY = -(0.1f * timeDelta - (obj)->anim.velocityY);
        if ((obj)->anim.velocityY < -10.0f)
        {
            (obj)->anim.velocityY = -10.0f;
        }
        (obj)->anim.localPosY = (obj)->anim.velocityY * timeDelta + (obj)->anim.
            localPosY;
        if ((obj)->anim.localPosY < icicle->dropY)
        {
            mainSetBits(placement->impactGameBit, 1);
            icicle->mode = DIM2ICICLE_MODE_IMPACTED;
            (*gWaterfxInterface)->spawnSplashBurst(
                (void*)obj, (obj)->anim.localPosX,
                icicle->dropY, (obj)->anim.localPosZ,
                10.0f);
            (*gWaterfxInterface)->spawnRipple(
                (obj)->anim.localPosX, icicle->dropY,
                (obj)->anim.localPosZ, 0, 0.0f, 2);
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_curtainopen16);
            icicle->timer = 0x96;
        }
        break;
    case DIM2ICICLE_MODE_IMPACTED:
    default:
        if (icicle->timer > 0)
        {
            icicle->timer -= framesThisStep;
            if (icicle->timer <= 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_155);
            }
        }
        {
            int v = (obj)->anim.alpha - framesThisStep * 8;
            if (v < 0)
            {
                v = 0;
                (obj)->anim.localPosY = placement->resetPosY;
                (obj)->anim.velocityY = 0.0f;
            }
            (obj)->anim.alpha = v;
        }
        (obj)->anim.localPosY = (obj)->anim.velocityY * timeDelta + (obj)->anim.
            localPosY;
        break;
    }
}

void dim2icicle_init(GameObject *obj, s8* p)
{
    Dim2IcicleState* icicle = (Dim2IcicleState*)obj->extra;
    Dim2iciclePlacement* placement = (Dim2iciclePlacement*)p;
    if (mainGetBit(placement->impactGameBit) != 0)
    {
        icicle->mode = DIM2ICICLE_MODE_IMPACTED;
        (obj)->anim.alpha = 0;
    }
    else
    {
        icicle->mode = DIM2ICICLE_MODE_WAIT_HIT;
        (obj)->anim.alpha = 0xff;
    }
    (obj)->anim.rotX = (s16)((s32)placement->initialRotX << 8);
    (obj)->anim.velocityY = 0.0f;
    (obj)->objectFlags |= DIM2ICICLE_OBJFLAG_HITDETECT_DISABLED;
}

void dim2icicle_release(void)
{
}

void dim2icicle_initialise(void)
{
}

ObjectDescriptor gDIM2IcicleObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dim2icicle_initialise,
    (ObjectDescriptorCallback)dim2icicle_release,
    0,
    (ObjectDescriptorCallback)dim2icicle_init,
    (ObjectDescriptorCallback)dim2icicle_update,
    (ObjectDescriptorCallback)dim2icicle_hitDetect,
    (ObjectDescriptorCallback)dim2icicle_render,
    (ObjectDescriptorCallback)dim2icicle_free,
    (ObjectDescriptorCallback)dim2icicle_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dim2icicle_getExtraSize,
};
