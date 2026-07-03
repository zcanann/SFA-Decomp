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
#include "main/obj_placement.h"

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);


FbWGPipe GXWGFifo : (0xCC008000);


#include "main/audio/sfx_ids.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"

#define DIM2CONVEYOR_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#define GAMEBIT_CONVEYOR_FORWARD   3163
#define GAMEBIT_CONVEYOR_REVERSE   3164
#define GAMEBIT_CONVEYOR_SWAP      3169
#define MAP_ID_SINGLE_BELT         7849
#define MAP_ID_DUAL_BELT           0x49B23
#define OBJ_GROUP_CONVEYORS        22
#define MUSIC_TRACK_CONVEYOR       0xdf

extern f32 lbl_803E4A58;

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


void dim2conveyor_hitDetect(void)
{
}

void dim2conveyor_release(void)
{
}

void dim2conveyor_initialise(void)
{
}


int dim2conveyor_getExtraSize(void) { return 0x14; }
int dim2conveyor_getObjectTypeId(void) { return 0x0; }

void dim2conveyor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4A58);
}


void dim2conveyor_free(int x) { ObjGroup_RemoveObject(x, OBJ_GROUP_CONVEYORS); }

void dim2conveyor_setScale(int* obj, int unused, f32* outX, f32* outY)
{
    extern void Music_Trigger(int id, int arg);
    Dim2ConveyorState* state = ((GameObject*)obj)->extra;
    int id;
    if (state->musicHold == 0)
    {
        Music_Trigger(MUSIC_TRACK_CONVEYOR, 1);
    }
    state->musicHold = 20;
    id = ((ObjPlacement*)((GameObject*)obj)->anim.placementData)->mapId;
    switch (id)
    {
    case MAP_ID_SINGLE_BELT:
        *outX = state->scrollX;
        *outY = state->scrollY;
        break;
    case MAP_ID_DUAL_BELT:
        if (GameBit_Get(GAMEBIT_CONVEYOR_REVERSE) != 0 && GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) == 0)
        {
            *outX = state->scrollX;
            *outY = state->scrollY;
        }
        if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) != 0 && GameBit_Get(GAMEBIT_CONVEYOR_REVERSE) == 0)
        {
            *outX = -state->scrollX;
            *outY = -state->scrollY;
        }
        if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) != 0)
        {
            GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 0);
        }
        if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) == 0)
        {
            GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 1);
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
    ObjGroup_AddObject((u32)obj, OBJ_GROUP_CONVEYORS);
    ((GameObject*)obj)->objectFlags |= DIM2CONVEYOR_OBJFLAG_HITDETECT_DISABLED;
    if (((ObjPlacement*)params)->mapId == MAP_ID_DUAL_BELT)
    {
        GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 1);
    }
}

void dim2conveyor_update(int* obj)
{
    extern void Music_Trigger(int id, int arg);

    Dim2ConveyorState* extra = ((GameObject*)obj)->extra;
    Sfx_PlayFromObject((int)obj, SFXfoot_metal_scuff);
    if (extra->musicHold != 0)
    {
        extra->musicHold = extra->musicHold - 1;
        if (extra->musicHold == 0)
        {
            Music_Trigger(MUSIC_TRACK_CONVEYOR, 0);
        }
    }
    switch (((ObjPlacement*)((GameObject*)obj)->anim.placementData)->mapId)
    {
    case MAP_ID_DUAL_BELT:
        if (GameBit_Get(GAMEBIT_CONVEYOR_SWAP) != 0)
        {
            extra->swapTimer = extra->swapTimer + timeDelta;
            if (extra->swapTimer > lbl_803E4A5C)
            {
                if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) != 0)
                {
                    GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 1);
                    GameBit_Set(GAMEBIT_CONVEYOR_FORWARD, 0);
                }
                else if (GameBit_Get(GAMEBIT_CONVEYOR_REVERSE) != 0)
                {
                    GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 0);
                    GameBit_Set(GAMEBIT_CONVEYOR_FORWARD, 1);
                }
                extra->swapTimer = lbl_803E4A60;
            }
        }
        if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) != 0)
        {
            GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 0);
        }
        if (GameBit_Get(GAMEBIT_CONVEYOR_FORWARD) == 0)
        {
            GameBit_Set(GAMEBIT_CONVEYOR_REVERSE, 1);
        }
        break;
    case MAP_ID_SINGLE_BELT:
        break;
    }
}
