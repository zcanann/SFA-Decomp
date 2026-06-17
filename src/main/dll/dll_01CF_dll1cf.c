/*
 * dll_1CF (dll1cf) - a small placement-driven object DLL. Only the
 * dll_1CF_* class entry points and the trigger-init FUN_801b7314 are
 * actually defined here; the surrounding STATIC_ASSERTs lock the shared
 * struct-pool layouts this re-split TU compiles against (sizes verified
 * against each class's getExtraSize), and GXWGFifo is the GX write-gather
 * FIFO mapping.
 *
 * dll_1CF_init reads its placement def (Dll1CFObjectDef): a gate game bit
 * at +0x1E arms the rotY setup, rotX comes from the +0x18 byte, and the
 * object flags get the 0xE000 bits. FUN_801b7314 is a trigger-init that
 * latches a marker into the extra block and, for placement mapId 0x49B23,
 * arbitrates the 0xC5B/0xC5C game-bit pair to pick the sign of the two
 * output floats.
 */

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
#include "main/game_object.h"
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

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);
/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

/* extra[4] latch value: denormal float whose bit pattern is 0x14. */
#define DLL1CF_TRIGGERED_MARKER 2.8026e-44

/* GameObject extra[] block slots used by FUN_801b7314. */
#define EXTRA_OUT_X 0
#define EXTRA_OUT_Y 1
#define EXTRA_TRIGGERED_MARKER 4

/* Placement mapId values arbitrated in FUN_801b7314. */
#define DLL1CF_MAP_GAMEBIT_PAIR 0x49b23
#define DLL1CF_MAP_PASSTHROUGH  0x1ea9

/* Game bits arbitrated in FUN_801b7314 (sign-of-output pair). */
#define GAMEBIT_DLL1CF_A 0xc5b
#define GAMEBIT_DLL1CF_B 0xc5c

/* FUN_800067c0 trigger event id, and the objectFlags bits set in dll_1CF_init. */
#define DLL1CF_TRIGGER_EVENT 0xdf
#define DLL1CF_OBJECT_FLAGS  0xe000

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void FUN_800067c0(int* param, int value);
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4A30;

/* GX write-gather pipe FIFO. */
volatile FbWGPipe GXWGFifo : (0xCC008000);

typedef struct Dll1CFObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;          /* 0x14: ObjPlacement mapId */
    s8 rotXByte;        /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1A - 0x19];
    s16 rotYRaw;        /* 0x1A: scaled into rotY when the gate bit is set */
    s16 unk1C;
    s16 gateGameBit;    /* 0x1E: game bit that enables the rotY setup */
} Dll1CFObjectDef;

/* load-bearing for this re-split TU's codegen - removing it shifts the .o. */
static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

/* These two fns intentionally compile with both passes ON / OFF respectively;
 * the off/on blocks scope exactly FUN_801b7314 and the entry points below them,
 * and the surrounding TU state is the default - no reset pair is needed. */
#pragma scheduling on
#pragma peephole on
/* obj is taken as int (not GameObject*) for param coloring (CLAUDE.md #126). */
void FUN_801b7314(int obj, undefined4 unused, float* outX, float* outY)
{
    uint bit;
    int mapId;
    float* extra;

    extra = ((GameObject*)obj)->extra;
    if (extra[EXTRA_TRIGGERED_MARKER] == 0.0)  /* first trigger only */
    {
        FUN_800067c0((int*)DLL1CF_TRIGGER_EVENT, 1);
    }
    extra[EXTRA_TRIGGERED_MARKER] = DLL1CF_TRIGGERED_MARKER;  /* mark as triggered (denormal = bit pattern 0x14) */
    mapId = ((ObjPlacement*)((GameObject*)obj)->anim.placementData)->mapId;
    if (mapId == DLL1CF_MAP_GAMEBIT_PAIR)
    {
        bit = GameBit_Get(GAMEBIT_DLL1CF_B);
        if ((bit != 0) && (bit = GameBit_Get(GAMEBIT_DLL1CF_A), bit == 0))
        {
            *outX = extra[EXTRA_OUT_X];
            *outY = extra[EXTRA_OUT_Y];
        }
        bit = GameBit_Get(GAMEBIT_DLL1CF_A);
        if ((bit != 0) && (bit = GameBit_Get(GAMEBIT_DLL1CF_B), bit == 0))
        {
            *outX = -extra[EXTRA_OUT_X];
            *outY = -extra[EXTRA_OUT_Y];
        }
        bit = GameBit_Get(GAMEBIT_DLL1CF_A);
        if (bit != 0)
        {
            GameBit_Set(GAMEBIT_DLL1CF_B, 0);
        }
        bit = GameBit_Get(GAMEBIT_DLL1CF_A);
        if (bit == 0)
        {
            GameBit_Set(GAMEBIT_DLL1CF_B, 1);
        }
    }
    /* the (mapId < ...) clause is redundant logically but load-bearing: it
     * emits the binary-search compare the target dispatch is built on. */
    else if ((mapId < DLL1CF_MAP_GAMEBIT_PAIR) && (mapId == DLL1CF_MAP_PASSTHROUGH))
    {
        *outX = extra[EXTRA_OUT_X];
        *outY = extra[EXTRA_OUT_Y];
    }
    else
    {
        *outX = extra[EXTRA_OUT_X];
        *outY = extra[EXTRA_OUT_Y];
    }
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

int dll_1CF_getExtraSize(void) { return 0x0; }
int dll_1CF_getObjectTypeId(void) { return 0x0; }

void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 visibleInt = visible; /* widen to s32 for cmpwi */
    if (visibleInt != 0) objRenderFn_8003b8f4(lbl_803E4A30);
}

void dll_1CF_init(GameObject* obj, Dll1CFObjectDef* def)
{
    if ((u32)GameBit_Get(def->gateGameBit) != 0u)
    {
        obj->anim.rotY = (s16)(((s32)def->rotYRaw << 13) / 45);
    }
    obj->anim.rotX = (s16)((s32)def->rotXByte << 8);
    obj->objectFlags = (u16)(obj->objectFlags | DLL1CF_OBJECT_FLAGS);
}
