/* DLL 0x1DD — DIM2 icicle / conveyor / crusher platform objects [801B8798-801B8860) */
#include "main/audio/sfx_ids.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"


/* dim2conveyor_getExtraSize == 0x14. */


STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

/* dll_1D6_getExtraSize == 0x20 (crusher platform). */


STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

/* dimtruthhornice_getExtraSize == 0x8. */


STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

/* dim2snowball_getExtraSize == 0xb0 (curve walker head + roll state). */


STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */


STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);


/*
 * --INFO--
 *
 * Function: dim_levelcontrol_update
 * EN v1.0 Address: 0x801B6464
 * EN v1.0 Size: 1352b
 * EN v1.1 Address: 0x801B6A18
 * EN v1.1 Size: 1352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern f32 timeDelta;


extern void objRenderFn_8003b8f4(f32);
extern int ObjHits_GetPriorityHit(int obj, void** outHitObj, int* outSphereIdx, uint* outHitVolume);
extern u8 lbl_803DBF20;
extern void* mmAlloc(int size, int a, int b);
extern u8 framesThisStep;

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DIM/DIM2projrock.h"
#include "main/objanim_internal.h"


typedef struct Dim2iciclePlacement
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x3 - 0x2];
    u8 unk3;
    u8 unk4;
    u8 pad5[0xC - 0x5];
    f32 unkC;
    u8 pad10[0x1E - 0x10];
    s16 unk1E;
} Dim2iciclePlacement;


extern int ObjHits_GetPriorityHit();


/*
 * --INFO--
 *
 * Function: FUN_801b8c60
 * EN v1.0 Address: 0x801B8C60
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801B8D60
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b9728
 * EN v1.0 Address: 0x801B9728
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B9578
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b972c
 * EN v1.0 Address: 0x801B972C
 * EN v1.0 Size: 448b
 * EN v1.1 Address: 0x801B97B8
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b9cc4
 * EN v1.0 Address: 0x801B9CC4
 * EN v1.0 Size: 104b
 * EN v1.1 Address: 0x801B9DC4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on
void FUN_801b9cc4(int param_1)
{
    char* pcVar1;
    int iVar2;

    pcVar1 = ((GameObject*)param_1)->extra;
    if ((pcVar1[2] & 1U) == 0)
    {
        iVar2 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0'))
        {
            pcVar1[2] = pcVar1[2] | 1;
            GameBit_Set((int)*(short*)(iVar2 + 0x1e), 1);
        }
    }
    return;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_1DA_release(void);


#pragma scheduling off
#pragma peephole off
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

extern u32 GameBit_Get(int id);
extern f32 lbl_803E4B80;

void dim2icicle_init(int obj, s8* p)
{
    char* inner = ((GameObject*)obj)->extra;
    if (GameBit_Get(*(s16*)(p + 0x1e)) != 0)
    {
        inner[6] = 2;
        ((GameObject*)obj)->anim.alpha = 0;
    }
    else
    {
        inner[6] = 0;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    *(s16*)obj = (s16)((s32)p[0x18] << 8);
    ((GameObject*)obj)->anim.velocityY = lbl_803E4B80;
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* dim2icefloe: per-frame curve-follow update + path-param init. */


/* dim2icicle_update: state machine -- wait for hit, shake, drop into water, melt. */
extern WaterfxInterface** gWaterfxInterface;
extern f32 lbl_803E4B6C;
extern f32 lbl_803E4B70;
extern f32 lbl_803E4B74;
extern f32 lbl_803E4B78;
extern f32 lbl_803E4B7C;

void dim2icicle_update(int obj)
{
    extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int* out, int a, int b);
    extern void Sfx_PlayFromObject(int obj, int sfxId);
    int sub;
    int state;
    state = *(int*)&((GameObject*)obj)->anim.placementData;
    sub = *(int*)&((GameObject*)obj)->extra;
    switch (((Dim2IcicleState*)sub)->mode)
    {
    case 0:
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0xe)
        {
            break;
        }
        ((Dim2IcicleState*)sub)->unk4 = (s16)randomGetRange(0x320, 0x4b0);
        ((Dim2IcicleState*)sub)->mode = 3;
        (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags &= ~1;
        Sfx_PlayFromObject(obj, SFXmv_cflap2_c);
        break;
    case 3:
        ((GameObject*)obj)->anim.rotY = ((Dim2IcicleState*)sub)->unk4;
        ((Dim2IcicleState*)sub)->unk4 = (f32)((Dim2IcicleState*)sub)->unk4 * lbl_803E4B6C;
        if (((GameObject*)obj)->anim.rotY >= 10)
        {
            break;
        }
        ((GameObject*)obj)->anim.rotY = 0;
        ((Dim2IcicleState*)sub)->mode = 1;
        ((Dim2IcicleState*)sub)->timer = 0x3c;
        break;
    case 1:
        if (((Dim2IcicleState*)sub)->unk7 == 0)
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
                ((Dim2IcicleState*)sub)->unk7 = 1;
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
            GameBit_Set(((Dim2iciclePlacement*)state)->unk1E, 1);
            ((Dim2IcicleState*)sub)->mode = 2;
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
    case 2:
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
                ((GameObject*)obj)->anim.localPosY = ((Dim2iciclePlacement*)state)->unkC;
                ((GameObject*)obj)->anim.velocityY = lbl_803E4B80;
            }
            ((GameObject*)obj)->anim.alpha = v;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        break;
    }
}

/* dll_1DB_update: geyser state machine driven by player standing on it. */
extern void Sfx_StopObjectChannel(int obj, int channel);

void dll_1DB_update(int obj);

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */


/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */


/* 8b "li r3, N; blr" returners. */
int dim2icicle_getExtraSize(void) { return 0xc; }
int dim2icicle_getObjectTypeId(void) { return 0x0; }
int dim2lavacontrol_getExtraSize(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4B68;


void dim2icicle_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B68);
}

void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


/* dll_1DA_init: stash obj->f10 into *(obj->p_B8), then bump obj->f10 by a constant step. */

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */


/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */

/* dim2lavacontrol_free: stop lava sfx, kill the lava music track, refresh time-of-day. */


/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */


/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */

