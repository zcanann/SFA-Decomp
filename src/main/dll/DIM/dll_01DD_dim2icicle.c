/* DLL 0x1DD — DIM2 Icicle: a swaying ceiling icicle that detects a hit,
 * waits, then drops to its target Y floor position and triggers a game-bit. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);



extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
#include "main/effect_interfaces.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2projrock.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"

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

void dim2icicle_free(void)
{
}

void dim2icicle_hitDetect(void)
{
}

void dim2icicle_release(void)
{
}

void dim2icicle_initialise(void)
{
}

void dim2icicle_init(int obj, s8* p)
{
    char* inner = ((GameObject*)obj)->extra;
    if (GameBit_Get(((Dim2iciclePlacement*)p)->impactGameBit) != 0)
    {
        inner[6] = DIM2ICICLE_MODE_IMPACTED;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    else
    {
        inner[6] = DIM2ICICLE_MODE_WAIT_HIT;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->anim.velocityY = lbl_803E4B80;
    ((GameObject*)obj)->objectFlags |= DIM2ICICLE_OBJFLAG_HITDETECT_DISABLED;
}

void dim2icicle_update(int obj)
{
    extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* out, int a, int b);

    ObjHitsPriorityState* hitState;
    int sub;
    int state;
    state = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    switch (((Dim2IcicleState*)sub)->mode)
    {
    case DIM2ICICLE_MODE_WAIT_HIT:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0xe)
        {
            break;
        }
        ((Dim2IcicleState*)sub)->wobbleRotY = randomGetRange(0x320, 0x4b0);
        ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_WOBBLE;
        hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
        hitState->flags &= ~1;
        Sfx_PlayFromObject(obj, SFXmv_cflap2_c);
        break;
    case DIM2ICICLE_MODE_WOBBLE:
        ((GameObject*)obj)->anim.rotY = ((Dim2IcicleState*)sub)->wobbleRotY;
        ((Dim2IcicleState*)sub)->wobbleRotY = (f32)((Dim2IcicleState*)sub)->wobbleRotY * lbl_803E4B6C;
        if (((GameObject*)obj)->anim.rotY >= 10)
        {
            break;
        }
        ((GameObject*)obj)->anim.rotY = 0;
        ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_DROP;
        ((Dim2IcicleState*)sub)->timer = 0x3c;
        break;
    case DIM2ICICLE_MODE_DROP:
        if (((Dim2IcicleState*)sub)->dropTargetFound == 0)
        {
            int n;
            int i;
            int list;
            n = hitDetectFn_80065e50(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                     ((GameObject*)obj)->anim.localPosZ, obj, &list, 0, 0);
            ((Dim2IcicleState*)sub)->dropY = lbl_803E4B70;
            for (i = 0; i < n; i++)
            {
                int p = *(int*)(list + i * 4);
                if (*(s8*)(p + 0x14) == 0xe)
                {
                    ((Dim2IcicleState*)sub)->dropY = *(f32*)p;
                    i = n;
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
                Sfx_PlayFromObject(obj, SFXmv_blockscrape_lp);
            }
        }
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E4B74 * timeDelta - ((GameObject*)obj)->anim.velocityY);
        if (((GameObject*)obj)->anim.velocityY < lbl_803E4B78)
        {
            ((GameObject*)obj)->anim.velocityY = *(f32*)&lbl_803E4B78;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        if (((GameObject*)obj)->anim.localPosY < ((Dim2IcicleState*)sub)->dropY)
        {
            GameBit_Set(((Dim2iciclePlacement*)state)->impactGameBit, 1);
            ((Dim2IcicleState*)sub)->mode = DIM2ICICLE_MODE_IMPACTED;
            (*gWaterfxInterface)->spawnSplashBurst(
                (void*)obj, ((GameObject*)obj)->anim.localPosX,
                ((Dim2IcicleState*)sub)->dropY, ((GameObject*)obj)->anim.localPosZ,
                lbl_803E4B7C);
            ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                ((GameObject*)obj)->anim.localPosX, ((Dim2IcicleState*)sub)->dropY,
                ((GameObject*)obj)->anim.localPosZ, 0, lbl_803E4B80, 2);
            Sfx_PlayFromObject(obj, SFXmv_missingcog_lp);
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
                Sfx_PlayFromObject(obj, SFXwp_sexpl2_c);
            }
        }
        {
            int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 8;
            if (v < 0)
            {
                v = 0;
                ((GameObject*)obj)->anim.localPosY = ((Dim2iciclePlacement*)state)->resetPosY;
                ((GameObject*)obj)->anim.velocityY = lbl_803E4B80;
            }
            ((GameObject*)obj)->anim.alpha = v;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        break;
    }
}

int dim2icicle_getExtraSize(void) { return 0xc; }
int dim2icicle_getObjectTypeId(void) { return 0x0; }

void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4B68);
}
