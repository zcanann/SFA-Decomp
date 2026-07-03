/*
 * dll_1CF (dll1cf) - a placement-driven static object. On init it reads its
 * placement def (Dll1CFObjectDef): a gate game bit at +0x1E arms the rotY
 * setup (scaled from the +0x1A raw), rotX comes from the +0x18 byte, and the
 * object flags get the 0xE000 bits.
 */

#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/explosion_state.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/object_descriptor.h"

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

/* objectFlags bits set in dll_1CF_init. */
#define DLL1CF_OBJECT_FLAGS 0xe000

extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4A30;

typedef struct Dll1CFObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 mapId;          /* 0x14: ObjPlacement mapId, not read by this DLL */
    s8 rotXByte;        /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1A - 0x19];
    s16 rotYRaw;        /* 0x1A: scaled into rotY when the gate bit is set */
    s16 unk1C;          /* 0x1C: not read */
    s16 gateGameBit;    /* 0x1E: game bit that enables the rotY setup */
} Dll1CFObjectDef;

/* The entry points compile with both passes OFF; the surrounding TU state is
 * the default, so no reset pair is needed. */
int dll_1CF_getExtraSize(void) { return 0x0; }
int dll_1CF_getObjectTypeId(void) { return 0x0; }

void dll_1CF_free(void)
{
}

void dll_1CF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 visibleInt = visible;
    if (visibleInt != 0) objRenderFn_8003b8f4(lbl_803E4A30);
}

void dll_1CF_hitDetect(void)
{
}

void dll_1CF_update(void)
{
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

void dll_1CF_release(void)
{
}

void dll_1CF_initialise(void)
{
}

ObjectDescriptor dll_1CF = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1CF_initialise,
    (ObjectDescriptorCallback)dll_1CF_release,
    0,
    (ObjectDescriptorCallback)dll_1CF_init,
    (ObjectDescriptorCallback)dll_1CF_update,
    (ObjectDescriptorCallback)dll_1CF_hitDetect,
    (ObjectDescriptorCallback)dll_1CF_render,
    (ObjectDescriptorCallback)dll_1CF_free,
    (ObjectDescriptorCallback)dll_1CF_getObjectTypeId,
    dll_1CF_getExtraSize,
};
