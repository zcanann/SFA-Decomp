/* === moved from main/dll/DIM/DIM2flameburst.c [801B63F4-801B6464) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/objseq.h"










/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */


STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */


STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);



STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped. REFERENCE-ONLY for now:
 * every consumer keeps raw derefs - retyping the state local (or adding
 * (int) casts) flips saved-reg coloring in init/update/render/fn_801B3DE4
 * (recipe #36/#77); the layout is documented here for a future pass.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);


/*
 * --INFO--
 *
 * Function: FUN_801b3de4
 * EN v1.0 Address: 0x801B3DE4
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x801B401C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_801b40f0
 * EN v1.0 Address: 0x801B40F0
 * EN v1.0 Size: 696b
 * EN v1.1 Address: 0x801B4398
 * EN v1.1 Size: 724b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: explosion_release
 * EN v1.0 Address: 0x801B5650
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B5DB8
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma scheduling off
#pragma peephole off

#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b5b8c
 * EN v1.0 Address: 0x801B5B8C
 * EN v1.0 Size: 372b
 * EN v1.1 Address: 0x801B62FC
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801b5d00
 * EN v1.0 Address: 0x801B5D00
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x801B64D0
 * EN v1.1 Size: 272b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/* Trivial 4b 0-arg blr leaves. */













#pragma scheduling off
#pragma peephole off

/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */





/* conditional init/free pair. */
#pragma scheduling on
#pragma peephole on

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */
extern void* Obj_GetPlayerObject(void);

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */
#pragma scheduling off

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */
#pragma peephole off


/* explosion_free: model-light release if present. */
#pragma scheduling on
#pragma peephole on

/* explosion_getObjectTypeId: tile/index lookup capped by table count. */
#pragma scheduling off

/* dim_levelcontrol_free: gameplay music + time-of-day reset. */


/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;
#pragma dont_inline on
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */
#pragma peephole off

extern f32 timeDelta;

/* EN v1.0 0x801B5804  size: 380b  dimwooddoor2_update: advance the door's
 * shake anim and decay its wobble; while idle near map-cue 0x338 bleed off
 * alpha, otherwise scan the nearby objects and, if a key object is present,
 * snap the door open (reset wobble, ring the gamebit, play the open sfx). */


/* EN v1.0 0x801B5AA0  size: 496b  dll_1CE_update: hatch-door logic - coast
 * the lid open with clamped velocity while idle, and once a key object is
 * nearby, count down then ring the gamebit and (if the load isn't locked)
 * spawn the contents object seeded from the door's transform. */



volatile FbWGPipe GXWGFifo : (0xCC008000);











#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/audio/sfx_ids.h"
#include "main/asset_load.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/DIM/DIM2snowball.h"
#include "main/objanim_internal.h"

typedef struct Dll1D6Placement
{
    u8 pad0[0x1A - 0x0];
    s16 upTimer;
    s16 downTimer;
    u8 pad1E[0x20 - 0x1E];
} Dll1D6Placement;












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

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

extern undefined4 FUN_800067c0();
extern undefined4 ObjHits_RecordObjectHit();


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



/*
 * --INFO--
 *
 * Function: FUN_801b6d24
 * EN v1.0 Address: 0x801B6D24
 * EN v1.0 Size: 404b
 * EN v1.1 Address: 0x801B6F60
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b6f88
 * EN v1.0 Address: 0x801B6F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801B71F4
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b6fa8
 * EN v1.0 Address: 0x801B6FA8
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801B721C
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801b7314
 * EN v1.0 Address: 0x801B7314
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x801B7708
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801b7314(int param_1, undefined4 param_2, float* param_3, float* param_4)
{
    uint uVar1;
    int iVar2;
    float* pfVar3;

    pfVar3 = ((GameObject*)param_1)->extra;
    if (pfVar3[4] == 0.0)
    {
        FUN_800067c0((int*)0xdf, 1);
    }
    pfVar3[4] = 2.8026e-44;
    iVar2 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    if (iVar2 == 0x49b23)
    {
        uVar1 = GameBit_Get(0xc5c);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5b), uVar1 == 0))
        {
            *param_3 = *pfVar3;
            *param_4 = pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5c), uVar1 == 0))
        {
            *param_3 = -*pfVar3;
            *param_4 = -pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 != 0)
        {
            GameBit_Set(0xc5c, 0);
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 == 0)
        {
            GameBit_Set(0xc5c, 1);
        }
    }
    else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9))
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    else
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    return;
}


/*
 * --INFO--
 *
 * Function: FUN_801b7fcc
 * EN v1.0 Address: 0x801B7FCC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801B8344
 * EN v1.1 Size: 1344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801b7fd0
 * EN v1.0 Address: 0x801B7FD0
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x801B8884
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_1CF_free(void);










void dll_1D6_hitDetect(void)
{
}

void dll_1D6_release(void)
{
}

void dll_1D6_initialise(void)
{
}

void dim2snowball_free(void);










/* 8b "li r3, N; blr" returners. */
int dll_1D6_getExtraSize(void) { return 0x20; }
int dll_1D6_getObjectTypeId(void) { return 0x0; }
int dim2snowball_getExtraSize(void);

/* 16b chained patterns. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E4A78;



void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4A78);
}

void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);


/* render-with-fn(lbl) (no visibility check). */

/* ObjGroup_RemoveObject(x, N) wrappers. */

/* dim2conveyor_setScale: per-area scale/sign + music latch for two specific map ids. */



/* dim2pathgenerator hitDetect: on hit type 0xE, scale velocity by const and SFX. */

extern void mm_free(void* p);
extern u8 lbl_803DBF20;

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */


void dll_1D6_free(int* obj)
{
    Dll1D6State* state = ((GameObject*)obj)->extra;
    if ((state->flags1D & 4) != 0)
    {
        state->flags1D = (u8)(state->flags1D & ~4);
    }
    mm_free(state->bufA);
    mm_free(state->bufB);
    (&lbl_803DBF20)[state->slot] = 0;
}

void dim2pathgenerator_init(int* obj, int* def);










extern void* mmAlloc(int size, int a, int b);
extern void ObjModel_SetBlendChannelTargets(int* model, int a, int b, int c, f32 w, int d);
extern void ObjModel_SetBlendChannelWeight(int* model, int a, f32 w);
extern s16 lbl_803DBF18;
extern f32 lbl_803E4A88;

void dll_1D6_init(int* obj, u8* params)
{
    Dll1D6State* extra;
    int* model;
    int i;

    *(s16*)obj = (s16)(*(s8*)((char*)params + 0x18) << 8);
    extra = ((GameObject*)obj)->extra;
    model = DIM2snowball_GetActiveModel(obj);
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A88, 0);
    ObjModel_SetBlendChannelWeight(model, 0, lbl_803E4A78);
    extra->upTimer = *(s16*)((char*)params + 0x1a);
    if (extra->upTimer < 15)
    {
        extra->upTimer = 15;
    }
    extra->downTimer = *(s16*)((char*)params + 0x1c);
    if (extra->downTimer < 15)
    {
        extra->downTimer = 15;
    }
    {
        f32 k = lbl_803E4A88;
        extra->hitRangeSqA = k * ((GameObject*)obj)->anim.rootMotionScale;
        extra->hitRangeSqA = extra->hitRangeSqA * extra->hitRangeSqA;
        extra->hitRangeSqB = k * ((GameObject*)obj)->anim.rootMotionScale;
        extra->hitRangeSqB = extra->hitRangeSqB * extra->hitRangeSqB;
    }
    extra->flags1D = GameBit_Get(496) ? 2 : 0;
    for (i = 0; i < 4; i++)
    {
        if ((&lbl_803DBF20)[i] == 0)
        {
            (&lbl_803DBF20)[i] = 1;
            extra->slot = i;
            i = 4;
        }
    }
    extra->bufA = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufA, 12, (&lbl_803DBF18)[extra->slot] * 40, 40);
    extra->bufB = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufB, 12,
                ((&lbl_803DBF18)[extra->slot] + 1) * 40, 40);
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

extern f32 lbl_803E4A40;




extern void mtxRotateByVec3s(f32 * mtx, s16 * ang);
extern void Matrix_TransformPoint(f32* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern f32 lbl_803E4A7C;
extern f32 lbl_803E4A80;
extern f32 lbl_803E4A84;
extern f32 lbl_803E4A8C;
extern f32 lbl_803E4A90;

void dll_1D6_update(int* obj)
{
    extern int* objFindTexture(int* obj, int a, int b);
    extern int Sfx_PlayFromObject(int obj, int sfxId);
    Dll1D6State* extra;
    int* def;
    int* model;
    int* tex;
    int* player;
    f32 mtx[20];
    s16 ang[6];
    f32 lx, ly, lz;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    extra = ((GameObject*)obj)->extra;

    if ((extra->flags1D & 1) != 0)
    {
        if ((extra->flags1D & 4) == 0)
        {
            extra->flags1D |= 4;
            extra->bobPhase = (f32)(int)
            randomGetRange(20, 40);
            extra->bobRate = (f32)(int)
            randomGetRange(6, 10) / lbl_803E4A7C;
        }
        extra->downTimer -= framesThisStep;
        extra->dizzyTimer = extra->dizzyTimer - framesThisStep;
        if (extra->dizzyTimer <= 0)
        {
            Sfx_PlayFromObject((int)obj, SFXmv_mushdizzylp12);
        }
        if (extra->downTimer <= 0)
        {
            model = DIM2snowball_GetActiveModel(obj);
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A80, 16);
            extra->upTimer = ((Dll1D6Placement*)def)->upTimer;
            if (extra->upTimer < 15)
            {
                extra->upTimer = 15;
            }
            extra->flags1D &= ~1;
            Sfx_PlayFromObject((int)obj, SFXfoot_metal_land);
        }
    }
    else
    {
        model = DIM2snowball_GetActiveModel(obj);
        if (*(int*)((char*)model + 0x28) != 0 && (extra->flags1D & 4) != 0)
        {
            if (*(f32*)*(int**)((char*)model + 0x28) >= lbl_803E4A78)
            {
                extra->flags1D &= ~4;
            }
        }
        extra->upTimer -= framesThisStep;
        if (extra->upTimer <= 0)
        {
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, lbl_803E4A84, 16);
            extra->downTimer = ((Dll1D6Placement*)def)->downTimer;
            if (extra->downTimer < 15)
            {
                extra->downTimer = 15;
            }
            extra->flags1D |= 1;
            Sfx_PlayFromObject((int)obj, SFXfoot_ice_scuff);
            extra->dizzyTimer = 20;
        }
    }
    tex = objFindTexture(obj, 0, 0);
    {
        s16 v = -*(s16*)((char*)tex + 0xa) + 256;
        if (v > 2048)
        {
            v = v - 2048;
        }
        *(s16*)((char*)tex + 0xa) = -v;
    }
    tex = objFindTexture(obj, 1, 0);
    {
        s16 v = -*(s16*)((char*)tex + 0xa) + 160;
        if (v > 2048)
        {
            v = v - 2048;
        }
        *(s16*)((char*)tex + 0xa) = -v;
    }
    player = (int*)Obj_GetPlayerObject();
    mtx[0] = -((GameObject*)obj)->anim.localPosX;
    mtx[1] = -((GameObject*)obj)->anim.localPosY;
    mtx[2] = -((GameObject*)obj)->anim.localPosZ;
    ang[0] = -*(s16*)obj;
    ang[1] = 0;
    ang[2] = 0;
    mtxRotateByVec3s(&mtx[3], ang);
    Matrix_TransformPoint(&mtx[3], ((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosY,
                          ((GameObject*)player)->anim.localPosZ, &lx, &ly, &lz);
    if ((extra->flags1D & 2) != 0)
    {
        ly = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
        if (ly < lbl_803E4A88)
        {
            ly = -ly;
        }
        if (ly < lbl_803E4A8C)
        {
            lz = lz * lz;
            if (lz <= extra->hitRangeSqA)
            {
                int* row;
                f32 lim;
                model = DIM2snowball_GetActiveModel(obj);
                row = *(int**)((char*)model + ((*(u16*)((char*)model + 0x18) >> 1) & 1) * 4 + 4);
                lim = ((GameObject*)obj)->anim.rootMotionScale *
                    (f32)(int) * (s16*)((char*)row + extra->hitRow * 16);
                if (lx <= lim)
                {
                    ObjHits_RecordObjectHit(player, obj, 11, 4, 0);
                }
            }
        }
    }
    if ((extra->flags1D & 4) != 0)
    {
        extra->bobPhase =
            extra->bobRate * timeDelta + extra->bobPhase;
        if (extra->bobPhase > lbl_803E4A90)
        {
            extra->bobRate = -(f32)(int)
            randomGetRange(6, 10) / lbl_803E4A7C;
            extra->bobPhase = lbl_803E4A90;
        }
        else if (extra->bobPhase < lbl_803E4A7C)
        {
            extra->bobRate = (f32)(int)
            randomGetRange(6, 10) / lbl_803E4A7C;
            extra->bobPhase = lbl_803E4A7C;
        }
    }
    if (GameBit_Get(496) != 0)
    {
        extra->flags1D |= 2;
    }
    else
    {
        extra->flags1D &= ~2;
    }
}

extern int Curve_AdvanceAlongPath(int* extra, f32 t);

