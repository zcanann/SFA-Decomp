/* DLL 0x1D6 - DIM2 crusher platform [801B63F4-801B6464) */
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
#include "main/objtexture.h"

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
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

/* dimwooddoor2 variant: trigger-init that loads a different float
 * (lbl_803E49F0) into the extra block's [4]. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

extern f32 timeDelta;

FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/asset_load.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/vecmath.h"

#define DLL1D6_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct Dll1D6Placement
{
    u8 pad0[0x1A - 0x0];
    s16 upTimer;
    s16 downTimer;
    u8 pad1E[0x20 - 0x1E];
} Dll1D6Placement;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern const f32 lbl_803E4A78;
extern u8 gDll1D6SlotInUse;
extern void ObjModel_SetBlendChannelTargets(int* model, int a, int b, int c, f32 w, int d);
extern void ObjModel_SetBlendChannelWeight(int* model, int a, f32 w);
extern s16 gDll1D6SlotTabIndex;
extern f32 lbl_803E4A88;
extern void Matrix_TransformPoint(f32* m, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern const f32 lbl_803E4A7C;
extern f32 lbl_803E4A80;
extern f32 lbl_803E4A84;
extern const f32 lbl_803E4A8C;
extern const f32 lbl_803E4A90;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on

#pragma scheduling off
#pragma peephole off
void dll_1D6_hitDetect(void)
{
}

void dll_1D6_release(void)
{
}

void dll_1D6_initialise(void)
{
}


int dll_1D6_getExtraSize(void) { return 0x20; }
int dll_1D6_getObjectTypeId(void) { return 0x0; }

void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4A78);
}


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
    (&gDll1D6SlotInUse)[state->slot] = 0;
}


void dll_1D6_init(int* obj, u8* params)
{
    Dll1D6State* extra;
    int* model;
    int i;

    ((GameObject*)obj)->anim.rotX = (s16)(*(s8*)((char*)params + 0x18) << 8);
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
        if ((&gDll1D6SlotInUse)[i] == 0)
        {
            (&gDll1D6SlotInUse)[i] = 1;
            extra->slot = i;
            i = 4;
        }
    }
    extra->bufA = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufA, 12, (&gDll1D6SlotTabIndex)[extra->slot] * 40, 40);
    extra->bufB = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufB, 12,
                ((&gDll1D6SlotTabIndex)[extra->slot] + 1) * 40, 40);
    ((GameObject*)obj)->objectFlags |= DLL1D6_OBJFLAG_HITDETECT_DISABLED;
}

#pragma opt_common_subs off
void dll_1D6_update(int* obj)
{
    Dll1D6State* extra;
    int* def;
    int* model;
    ObjTextureRuntimeSlot* tex;
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
            Sfx_PlayFromObject((u32)obj, SFXmv_mushdizzylp12);
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
            Sfx_PlayFromObject((u32)obj, SFXfoot_metal_land);
        }
    }
    else
    {
        void* p28;
        model = DIM2snowball_GetActiveModel(obj);
        p28 = *(void**)((char*)model + 0x28);
        if (p28 != NULL && (extra->flags1D & 4) != 0)
        {
            if (*(f32*)p28 >= lbl_803E4A78)
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
            Sfx_PlayFromObject((u32)obj, SFXfoot_ice_scuff);
            extra->dizzyTimer = 20;
        }
    }
    tex = objFindTexture(obj, 0, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 256;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    tex = objFindTexture(obj, 1, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 160;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    player = Obj_GetPlayerObject();
    mtx[0] = -((GameObject*)obj)->anim.localPosX;
    mtx[1] = -((GameObject*)obj)->anim.localPosY;
    mtx[2] = -((GameObject*)obj)->anim.localPosZ;
    ang[0] = -((GameObject*)obj)->anim.rotX;
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
                {
                    char* mrow = (char*)model + 4;
                    row = *(int**)(mrow + ((*(u16*)((char*)model + 0x18) >> 1) & 1) * 4);
                }
                lim = ((GameObject*)obj)->anim.rootMotionScale *
                    (f32)(int) * (s16*)((char*)row + extra->hitRow * 16);
                if (lx <= lim)
                {
                    ObjHits_RecordObjectHit((int)player, (int)obj, 11, 4, 0);
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
#pragma opt_common_subs reset
