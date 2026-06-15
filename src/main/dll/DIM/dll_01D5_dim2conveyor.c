/* DLL 0x1D5 — DIM 2 conveyor belt object. Scrolls two texture channels on a conveyor mesh using
 * sin/cos of a placement-defined rotation angle. For map id 0x49B23 (the dual-direction belt),
 * manages forward/reverse direction via game bits 3163/3164 with a timed swap (swapTimer). Adds
 * itself to object group 22; music track 0xDF is kept alive while the belt is moving. */
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

extern f32 timeDelta;

volatile FbWGPipe GXWGFifo : (0xCC008000);

extern f32 mathSinf(f32 x);

#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/objlib.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern undefined4 FUN_800067c0();
extern f32 lbl_803E4A58;
extern f32 mathCosf(f32 x);
extern f32 lbl_803E4A5C;
extern f32 lbl_803E4A60;
extern f32 lbl_803E4A64;
extern f32 lbl_803E4A68;
extern f32 lbl_803E4A6C;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void dll_1CF_free(void);

#pragma scheduling off
#pragma peephole off
void dim2conveyor_hitDetect(void)
{
}

void dim2conveyor_release(void)
{
}

void dim2conveyor_initialise(void)
{
}

void dll_1D6_hitDetect(void);

int dim2conveyor_getExtraSize(void) { return 0x14; }
int dim2conveyor_getObjectTypeId(void) { return 0x0; }
int dll_1D6_getExtraSize(void);

void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4A58);
}

void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dim2conveyor_free(int x) { ObjGroup_RemoveObject(x, 0x16); }

void dim2conveyor_setScale(int* obj, int unused, f32* outX, f32* outY)
{
    extern void Music_Trigger(int trackId, int restart);
    Dim2ConveyorState* state = ((GameObject*)obj)->extra;
    int id;
    if (state->musicHold == 0)
    {
        Music_Trigger(0xdf, 1);
    }
    state->musicHold = 20;
    id = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    switch (id)
    {
    case 7849:
        *outX = state->scrollX;
        *outY = state->scrollY;
        break;
    case 0x49B23:
        if (GameBit_Get(3164) != 0 && GameBit_Get(3163) == 0)
        {
            *outX = state->scrollX;
            *outY = state->scrollY;
        }
        if (GameBit_Get(3163) != 0 && GameBit_Get(3164) == 0)
        {
            *outX = -state->scrollX;
            *outY = -state->scrollY;
        }
        if (GameBit_Get(3163) != 0)
        {
            GameBit_Set(3164, 0);
        }
        if (GameBit_Get(3163) == 0)
        {
            GameBit_Set(3164, 1);
        }
        break;
    default:
        *outX = state->scrollX;
        *outY = state->scrollY;
        break;
    }
}

void dim2conveyor_init(int* obj, u8* params)
{
    f32 scale = (f32) * (s16*)((char*)params + 0x1a) / lbl_803E4A64;
    Dim2ConveyorState* extra;
    *(s16*)obj = (s16)(*(s8*)((char*)params + 0x18) << 8);
    extra = ((GameObject*)obj)->extra;
    extra->scrollX = scale * mathSinf(lbl_803E4A68 * (f32) * (s16*)obj / lbl_803E4A6C);
    extra->scrollY = scale * mathCosf(lbl_803E4A68 * (f32) * (s16*)obj / lbl_803E4A6C);
    extra->swapTimer = lbl_803E4A60;
    extra->musicHold = 0;
    ObjGroup_AddObject((u32)obj, 22);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    if (*(u32*)((char*)params + 0x14) == 0x49b23)
    {
        GameBit_Set(3164, 1);
    }
}

void dim2conveyor_update(int* obj)
{
    extern void Music_Trigger(int trackId, int restart);
    extern int Sfx_PlayFromObject(int obj, int sfxId);
    Dim2ConveyorState* extra = ((GameObject*)obj)->extra;
    Sfx_PlayFromObject((int)obj, SFXfoot_metal_scuff);
    if (extra->musicHold != 0)
    {
        extra->musicHold = extra->musicHold - 1;
        if (extra->musicHold == 0)
        {
            Music_Trigger(223, 0);
        }
    }
    switch (*(int*)((char*)*(int**)&((GameObject*)obj)->anim.placementData + 0x14))
    {
    case 0x49b23:
        if (GameBit_Get(3169) != 0)
        {
            extra->swapTimer = extra->swapTimer + timeDelta;
            if (extra->swapTimer > lbl_803E4A5C)
            {
                if (GameBit_Get(3163) != 0)
                {
                    GameBit_Set(3164, 1);
                    GameBit_Set(3163, 0);
                }
                else if (GameBit_Get(3164) != 0)
                {
                    GameBit_Set(3164, 0);
                    GameBit_Set(3163, 1);
                }
                extra->swapTimer = lbl_803E4A60;
            }
        }
        if (GameBit_Get(3163) != 0)
        {
            GameBit_Set(3164, 0);
        }
        if (GameBit_Get(3163) == 0)
        {
            GameBit_Set(3164, 1);
        }
        break;
    case 7849:
        break;
    }
}
