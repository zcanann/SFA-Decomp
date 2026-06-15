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

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

volatile FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

#include "main/game_object.h"

typedef struct Dll1CFObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dll1CFObjectDef;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern undefined4 FUN_800067c0();
extern f32 lbl_803E4A30;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on
void FUN_801b7314(int param_1, undefined4 param_2, float* param_3, float* param_4)
{
    uint bitValue;
    int typeId;
    float* extra;

    extra = ((GameObject*)param_1)->extra;
    if (extra[4] == 0.0)
    {
        FUN_800067c0((int*)0xdf, 1);
    }
    extra[4] = 2.8026e-44;
    typeId = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    if (typeId == 0x49b23)
    {
        bitValue = GameBit_Get(0xc5c);
        if ((bitValue != 0) && (bitValue = GameBit_Get(0xc5b), bitValue == 0))
        {
            *param_3 = *extra;
            *param_4 = extra[1];
        }
        bitValue = GameBit_Get(0xc5b);
        if ((bitValue != 0) && (bitValue = GameBit_Get(0xc5c), bitValue == 0))
        {
            *param_3 = -*extra;
            *param_4 = -extra[1];
        }
        bitValue = GameBit_Get(0xc5b);
        if (bitValue != 0)
        {
            GameBit_Set(0xc5c, 0);
        }
        bitValue = GameBit_Get(0xc5b);
        if (bitValue == 0)
        {
            GameBit_Set(0xc5c, 1);
        }
    }
    else if ((typeId < 0x49b23) && (typeId == 0x1ea9))
    {
        *param_3 = *extra;
        *param_4 = extra[1];
    }
    else
    {
        *param_3 = *extra;
        *param_4 = extra[1];
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void dll_1CF_free(void)
{
}

void dll_1CF_hitDetect(void)
{
}

void dll_1CF_update(void)
{
}

void dll_1CF_release(void)
{
}

void dll_1CF_initialise(void)
{
}

void dim_tricky_free(void);

int dll_1CF_getExtraSize(void) { return 0x0; }
int dll_1CF_getObjectTypeId(void) { return 0x0; }
int dim_tricky_getExtraSize(void);

void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4A30);
}

void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */

void dll_1CF_init(int* obj, int* def)
{
    if ((u32)GameBit_Get(((Dll1CFObjectDef*)def)->unk1E) != 0u)
    {
        ((GameObject*)obj)->anim.rotY = (s16)(((s32)((Dll1CFObjectDef*)def)->unk1A << 13) / 45);
    }
    *(s16*)obj = (s16)((s32)((Dll1CFObjectDef*)def)->unk18 << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0xe000);
}
