/* DLL 0x1DD — DIM2 Icicle: a swaying ceiling icicle that detects a hit,
 * waits, then drops to its target Y floor position and triggers a game-bit. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"
#include "main/object_render_legacy.h"
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
    u8 pad10[0x1E - 0x10];
    s16 impactGameBit;
} Dim2iciclePlacement;

extern f32 lbl_803E4B80;
extern f32 lbl_803E4B6C;
extern f32 lbl_803E4B70;
extern f32 lbl_803E4B74;
extern f32 lbl_803E4B78;
extern f32 lbl_803E4B7C;
extern f32 lbl_803E4B68;

int dim2icicle_getExtraSize(void) { return 0xc; }

int dim2icicle_getObjectTypeId(void) { return 0x0; }


void dim2icicle_free(void)
{
}

void dim2icicle_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E4B68);
}


void dim2icicle_hitDetect(void)
{
}

void dim2icicle_update(GameObject *obj)
{
    ObjHitsPriorityState* hitState;
    int sub;
    int state;
    state = *(int*)&(obj)->anim.placementData;
    sub = *(int*)&(obj)->extra;
    switch (((Dim2IcicleState*)sub)->mode)
    {
    case DIM2ICICLE_MODE_WAIT_HIT:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0xe)
        {
            break;
        }
        ((Dim2IcicleState*)sub)->wobbleRotY = randomGetRange(0x320, 0x4b0);
        ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_WOBBLE;
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        hitState->flags &= ~1;
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_sbalhis6);
        break;
    case DIM2ICICLE_MODE_WOBBLE:
        (obj)->anim.rotY = ((Dim2IcicleState*)sub)->wobbleRotY;
        ((Dim2IcicleState*)sub)->wobbleRotY = (f32)((Dim2IcicleState*)sub)->wobbleRotY * *(f32*)&lbl_803E4B6C;
        if ((obj)->anim.rotY >= 10)
        {
            break;
        }
        (obj)->anim.rotY = 0;
        ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_DROP;
        ((Dim2IcicleState*)sub)->timer = 0x3c;
        break;
    case DIM2ICICLE_MODE_DROP:
        if (((Dim2IcicleState*)sub)->dropTargetFound == 0)
        {
            int hitCount;
            int i;
            TrackGroundHit** list;
            hitCount = hitDetectFn_80065e50(obj, (obj)->anim.localPosX, (obj)->anim.localPosY,
                                            (obj)->anim.localPosZ, &list, 0, 0);
            ((Dim2IcicleState*)sub)->dropY = lbl_803E4B70;
            for (i = 0; i < hitCount; i++)
            {
                TrackGroundHit* hit = list[i];
                if ((s8)hit->surfaceType == 0xe)
                {
                    ((Dim2IcicleState*)sub)->dropY = hit->height;
                    i = hitCount;
                }
            }
            if (lbl_803E4B70 != ((Dim2IcicleState*)sub)->dropY)
            {
                ((Dim2IcicleState*)sub)->dropTargetFound = 1;
            }
        }
        if (((Dim2IcicleState*)sub)->timer > 0)
        {
            ((Dim2IcicleState*)sub)->timer -= framesThisStep;
            if (((Dim2IcicleState*)sub)->timer <= 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_swdwood16);
            }
        }
        (obj)->anim.velocityY = -(lbl_803E4B74 * timeDelta - (obj)->anim.velocityY);
        if ((obj)->anim.velocityY < lbl_803E4B78)
        {
            (obj)->anim.velocityY = *(f32*)&lbl_803E4B78;
        }
        (obj)->anim.localPosY = (obj)->anim.velocityY * timeDelta + (obj)->anim.
            localPosY;
        if ((obj)->anim.localPosY < ((Dim2IcicleState*)sub)->dropY)
        {
            mainSetBits(((Dim2iciclePlacement*)state)->impactGameBit, 1);
            ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_IMPACTED;
            (*gWaterfxInterface)->spawnSplashBurst(
                (void*)obj, (obj)->anim.localPosX,
                ((Dim2IcicleState*)sub)->dropY, (obj)->anim.localPosZ,
                lbl_803E4B7C);
            (*gWaterfxInterface)->spawnRipple(
                (obj)->anim.localPosX, ((Dim2IcicleState*)sub)->dropY,
                (obj)->anim.localPosZ, 0, lbl_803E4B80, 2);
            Sfx_PlayFromObject((int)obj, SFXTRIG_mv_curtainopen16);
            ((Dim2IcicleState*)sub)->timer = 0x96;
        }
        break;
    case DIM2ICICLE_MODE_IMPACTED:
    default:
        if (((Dim2IcicleState*)sub)->timer > 0)
        {
            ((Dim2IcicleState*)sub)->timer -= framesThisStep;
            if (((Dim2IcicleState*)sub)->timer <= 0)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_155);
            }
        }
        {
            int v = (obj)->anim.alpha - framesThisStep * 8;
            if (v < 0)
            {
                v = 0;
                (obj)->anim.localPosY = ((Dim2iciclePlacement*)state)->resetPosY;
                (obj)->anim.velocityY = lbl_803E4B80;
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
    char* inner = (obj)->extra;
    if (mainGetBit(((Dim2iciclePlacement*)p)->impactGameBit) != 0)
    {
        inner[6] = DIM2ICICLE_MODE_IMPACTED;
        (obj)->anim.alpha = 0;
    }
    else
    {
        inner[6] = DIM2ICICLE_MODE_WAIT_HIT;
        (obj)->anim.alpha = 0xff;
    }
    (obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    (obj)->anim.velocityY = lbl_803E4B80;
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
