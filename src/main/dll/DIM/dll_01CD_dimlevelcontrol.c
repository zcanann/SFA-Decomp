/* DLL 0x01CD — DIM level-control objects [801B63F4-801B6464) */
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
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/sky_interface.h"

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

extern f32 lbl_803E4A20;
extern void dimmagicbridge_scrollTextureChannels(int obj, u8* sub);
extern void timeOfDayFn_80055000(void);
extern u8 framesThisStep;
extern f32 timeDelta;
STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);
extern undefined4 FUN_800067c0();
extern void getEnvfxActImmediately(int a, int b, int id, int d);
extern void getEnvfxAct(int a, int b, int id, int d);
extern void gameTextSetColor(int r, int g, int b, int a);
extern void gameTextShow(int id);
extern void SCGameBitLatch_Update(int* state, int mask, int a, int b, int bit, int value);
extern f32 lbl_803E4A24;
extern f32 lbl_803E4A28;
extern int getSaveGameLoadStatus(void);
extern void gameBitFn_800ea2e0(u8 n);
extern void unlockLevel(int a, int b, int c);

int dim_levelcontrol_getExtraSize(void) { return 0x10; }

void dim_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(int p1, int p2, int p3, int p4, int p5, f32 v);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4A20);
}

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

#pragma peephole on
void dim_levelcontrol_free(int p1)
{
    extern void Music_Trigger(s32 triggerId, s32 mode);
    Music_Trigger(0xa1, 0);
    Music_Trigger(0xed, 0);
    timeOfDayFn_80055000();
}

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
#pragma dont_inline on
void dimmagicbridge_scrollTextureChannels(int arg1, u8* obj);
#pragma dont_inline reset

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

volatile FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

#pragma peephole off
static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

typedef struct DimLevelControlState
{
    f32 timer;
    int latch;
    u8 saveState;
    u8 unk9;
    s16 musicTrack;
    u8 unkC;
    u8 unkD;
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
} DimLevelControlState;

void dim_levelcontrol_update(int obj)
{
    extern void Music_Trigger(int id, int value);
    extern int Sfx_PlayFromObject(int obj, int id);
    u8 a;
    u8 b;
    u8 c;
    u8 d;
    DimLevelControlState* st;
    u32 t;
    u32 t2;

    a = GameBit_Get(0xd0b);
    b = GameBit_Get(0xd0c);
    c = GameBit_Get(0xd0d);
    d = GameBit_Get(0xd0e);
    st = ((GameObject*)obj)->extra;
    if ((a && !st->b7) || (b && !st->b6) || (c && !st->b5) || (d && !st->b4))
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    st->b7 = a;
    st->b6 = b;
    st->b5 = c;
    st->b4 = d;
    if (!st->b3 && (u32)GameBit_Get(0xa21) != 0)
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        st->b3 = 1;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((u32)GameBit_Get(0xa82) == 0 ||
            ((u32)GameBit_Get(0x17) != 0 && (u32)GameBit_Get(0xead) == 0))
        {
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(0, 0, 0x160, 0);
                getEnvfxActImmediately(0, 0, 0x15a, 0);
                getEnvfxActImmediately(0, 0, 0x15c, 0);
                getEnvfxActImmediately(0, 0, 0x15f, 0);
            }
            else
            {
                getEnvfxAct(0, 0, 0x160, 0);
                getEnvfxAct(0, 0, 0x15a, 0);
                getEnvfxAct(0, 0, 0x15c, 0);
                getEnvfxAct(0, 0, 0x15f, 0);
            }
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    if (st->unkD != 0)
    {
        if ((u32)GameBit_Get(0x651) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(0x13, 0xd, 0);
            st->unkD = 0;
        }
    }
    else
    {
        if ((u32)GameBit_Get(0x651) != 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(0x13, 0xd, 1);
            st->unkD = 1;
        }
    }
    if (st->timer > lbl_803E4A24)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x430);
        st->timer = st->timer - timeDelta;
        if (st->timer < *(f32*)&lbl_803E4A24)
        {
            st->timer = lbl_803E4A24;
        }
    }
    if (st->unkC == 0)
    {
        t = GameBit_Get(0x3e2);
        t2 = GameBit_Get(0x3e3);
        st->unkC = (u8)(t2 & t);
        if (st->unkC != 0)
        {
            (*gGameUIInterface)->showNpcDialogue(0x4ba, 0x14, 0x8c, 1);
        }
    }
    t = GameBit_Get(0x3e2);
    {
        int gb = !GameBit_Get(0x3e3);
        t = gb & t;
    }
    t2 = t & 0xff;
    if (t2 != st->saveState)
    {
        GameBit_Set(0x3e8, t2);
        st->saveState = t2;
    }
    if (!(u8)GameBit_Get(0x8a5) && (u32)GameBit_Get(0x89d) != 0)
    {
        GameBit_Set(0x8a4, 1);
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0)
    {
        if (st->musicTrack != 0xe2)
        {
            st->musicTrack = 0xe2;
            if (st->latch & 4)
            {
                Music_Trigger(0xc5, 0);
                Music_Trigger(0xe2, 1);
            }
        }
    }
    else
    {
        if (st->musicTrack != 0xc5)
        {
            st->musicTrack = 0xc5;
            if (st->latch & 4)
            {
                Music_Trigger(0xe2, 0);
                Music_Trigger(0xc5, 1);
            }
        }
    }
    SCGameBitLatch_Update(&st->latch, 1, 0x1a7, 0x64b, 0xc1e, 0xa1);
    SCGameBitLatch_Update(&st->latch, 2, 0x1a8, 0xc0, 0xc1f, 0xcf);
    SCGameBitLatch_Update(&st->latch, 4, 0x1ba, 0x1b9, 0xc20, st->musicTrack);
    SCGameBitLatch_Update(&st->latch, 8, -1, -1, 0xd8f, 0xdc);
    SCGameBitLatch_Update(&st->latch, 0x10, 0x1a7, 0x64b, 0xc1e, 0xed);
    SCGameBitLatch_Update(&st->latch, 0x20, 0x1a8, 0xc0, 0xc1f, 0x36);
    SCGameBitLatch_Update(&st->latch, 0x40, 0x1ba, 0x1b9, 0xc20, 0x35);
    SCGameBitLatch_Update(&st->latch, 0x100, -1, -1, 0x3e2, 0x2b);
}

#pragma scheduling on
#pragma peephole on
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

void dll_1CF_free(void);

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */

#pragma scheduling off
#pragma peephole off
void dim_levelcontrol_init(int obj)
{
    DimLevelControlState* st;
    u8 i;

    randomGetRange(0, 11);
    st = ((GameObject*)obj)->extra;
    st->saveState = 0;
    st->timer = lbl_803E4A28;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    for (i = 1; i <= 38; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    st->unkC = (u8)GameBit_Get(0xdc);
    GameBit_Set(0xf0a, 0);
    if ((u32)GameBit_Get(0x89d) != 0 && (u32)GameBit_Get(0x8a5) == 0)
    {
        GameBit_Set(0x89d, 0);
    }
    st->b7 = (u8)GameBit_Get(0xd0b);
    st->b6 = (u8)GameBit_Get(0xd0c);
    st->b5 = (u8)GameBit_Get(0xd0d);
    st->b4 = (u8)GameBit_Get(0xd0e);
    st->b3 = (u8)GameBit_Get(0xa21);
    (*gMapEventInterface)->setMapAct(((GameObject*)obj)->anim.mapEventSlot, 1);
    ((GameObject*)obj)->objectFlags |= 0x6000;
    unlockLevel(0, 0, 1);
}

void dim_tricky_update(int* obj);
