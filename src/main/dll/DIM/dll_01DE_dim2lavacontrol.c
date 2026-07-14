/* DLL 0x1DE — DIM2 Lava Control: manages the DIM2 lava-rise sequence —
 * triggers env-fx transitions, drives music track changes based on player
 * carry state, and maintains the countdown-armed SCGameBitLatch triggers. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/savegame_load_api.h"
#include "main/audio/music_api.h"
#include "main/sky_api.h"
#include "main/render_envfx_api.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "main/object_render_legacy.h"
#include "main/rcp_dolphin_api.h"
#include "main/dll/player_objects.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* DIM2PathGenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);



#include "main/gamebits.h"
#include "main/audio/music_trigger_ids.h"

u8 lbl_803DBF28[8] = {0xFF, 0xCD, 0xB9, 0xAA, 0, 0, 0, 0};

/* Env-effect ids co-activated on the unkF4 restore tick (immediately when
   unkF4==2, else deferred); opaque distinct roles per index. */
#define DIM2LAVACONTROL_ENVFX_A 0x163
#define DIM2LAVACONTROL_ENVFX_B 0x166
#define DIM2LAVACONTROL_ENVFX_C 0x165
#define DIM2LAVACONTROL_ENVFX_D 0x164

typedef struct Dim2lavacontrolPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s8 unk18;
    u8 unk19;
    u8 unk1A;
    u8 unk1B;
    s16 unk1C;
    s16 gameBit;
} Dim2lavacontrolPlacement;

typedef struct Dim2lavacontrolState
{
    s8 countdown;
    u8 countdownSave;
    s8 flags;
    u8 sfxLevel;
    u8 phase;
    u8 pad5[0xC - 0x5];
    int musicTrack;
    u8 padC[0x24 - 0x10];
    f32 unk24;
} Dim2lavacontrolState;

typedef enum Dim2lavacontrolPhase
{
    DIM2LAVACONTROL_PHASE_WAIT = 0,      /* waits for its unlock game bit */
    DIM2LAVACONTROL_PHASE_TRIGGERED = 1, /* unlock bit set; control latched */
} Dim2lavacontrolPhase;

extern f32 lbl_803E4B90;
extern void fn_8004C1E4(int sfxId, f32 vol);
extern u8 lbl_803DBF28[8];

void dim2lavacontrol_setScale(GameObject *obj)
{
    void* sub = (obj)->extra;
    if (((s32)((Dim2lavacontrolState*)sub)->flags & 1) == 0)
    {
        void* p = *(void**)&(obj)->anim.placementData;
        if ((s32)((Dim2lavacontrolState*)sub)->countdown > 0)
        {
            ((Dim2lavacontrolState*)sub)->countdown -= 1;
            if (((Dim2lavacontrolState*)sub)->countdown == 0)
            {
                ((Dim2lavacontrolState*)sub)->flags = (s8)(*(u8*)&((Dim2lavacontrolState*)sub)->flags | 1);
                mainSetBits(((Dim2lavacontrolPlacement*)p)->gameBit, 1);
            }
        }
    }
}

int dim2lavacontrol_getExtraSize(void) { return 0x10; }

void dim2lavacontrol_free(void)
{
    fn_8004C1E4(0xC0, lbl_803E4B90);
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    timeOfDayFn_80055000();
}

void dim2lavacontrol_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E4B90);
}

#pragma opt_common_subs off
void dim2lavacontrol_update(int obj)
{
    int diff;
    GameObject* heldObj;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->unkF4 == 2)
        {
            getEnvfxActImmediatelyInt(0, 0, DIM2LAVACONTROL_ENVFX_A, 0);
            getEnvfxActImmediatelyInt(0, 0, DIM2LAVACONTROL_ENVFX_B, 0);
            getEnvfxActImmediatelyInt(0, 0, DIM2LAVACONTROL_ENVFX_C, 0);
            getEnvfxActImmediatelyInt(0, 0, DIM2LAVACONTROL_ENVFX_D, 0);
        }
        else
        {
            getEnvfxActInt(0, 0, DIM2LAVACONTROL_ENVFX_A, 0);
            getEnvfxActInt(0, 0, DIM2LAVACONTROL_ENVFX_B, 0);
            getEnvfxActInt(0, 0, DIM2LAVACONTROL_ENVFX_C, 0);
            getEnvfxActInt(0, 0, DIM2LAVACONTROL_ENVFX_D, 0);
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    obj = *(int*)&((GameObject*)obj)->extra;
    switch (((Dim2lavacontrolState*)obj)->phase)
    {
    case DIM2LAVACONTROL_PHASE_WAIT:
        if (mainGetBit(0xacd) != 0)
        {
            mainSetBits(0xcc3, 1);
            ((Dim2lavacontrolState*)obj)->phase = DIM2LAVACONTROL_PHASE_TRIGGERED;
        }
        break;
    case DIM2LAVACONTROL_PHASE_TRIGGERED:
        break;
    }
    diff = ((Dim2lavacontrolState*)obj)->sfxLevel - lbl_803DBF28[((Dim2lavacontrolState*)obj)->countdown];
    if (diff != 0)
    {
        if (diff > 0)
        {
            ((Dim2lavacontrolState*)obj)->sfxLevel -= 1;
        }
        else
        {
            ((Dim2lavacontrolState*)obj)->sfxLevel += 1;
        }
        fn_8004C1E4(((Dim2lavacontrolState*)obj)->sfxLevel, lbl_803E4B90);
    }
    if (Player_GetHeldObject(Obj_GetPlayerObject(), &heldObj) != 0)
    {
        if ((*(int*)&((GameObject*)obj)->anim.rootMotionScale & 2) && *(int*)&((GameObject*)obj)->anim.localPosX !=
            0xe0)
        {
            Music_Trigger(*(int*)&((GameObject*)obj)->anim.localPosX, 0);
            *(int*)&((GameObject*)obj)->anim.localPosX = 0xe0;
            Music_Trigger(MUSICTRIG_WLC_Puzzle_e0, 1);
        }
    }
    else
    {
        if ((*(int*)&((GameObject*)obj)->anim.rootMotionScale & 2) && *(int*)&((GameObject*)obj)->anim.localPosX !=
            0xd7)
        {
            Music_Trigger(*(int*)&((GameObject*)obj)->anim.localPosX, 0);
            *(int*)&((GameObject*)obj)->anim.localPosX = 0xd7;
            Music_Trigger(MUSICTRIG_WLC_Chambers, 1);
        }
    }
    SCGameBitLatch_Update((SCGameBitLatchState*)((char*)obj + 8), 1, -1, -1, 0xd99, 0xde);
    SCGameBitLatch_Update((SCGameBitLatchState*)((char*)obj + 8), 2, -1, -1, 0xda5,
                          *(int*)&((GameObject*)obj)->anim.localPosX);
    SCGameBitLatch_Update((SCGameBitLatchState*)((char*)obj + 8), 8, -1, -1, 0xf04, 0x96);
    SCGameBitLatch_UpdateInverted((SCGameBitLatchState*)((char*)obj + 8), 0x10, -1, -1, 0xf04, 0x2c);
    SCGameBitLatch_Update((SCGameBitLatchState*)((char*)obj + 8), 4, -1, -1, 0xcbb, 0xc4);
}
#pragma opt_common_subs reset

void dim2lavacontrol_init(GameObject *obj, int param2)
{
    extern void gameBitFn_800ea2e0(int i);
    int state;
    int i;
    int gameBitState;
    if (getSaveGameLoadStatus() != 0)
    {
        (obj)->unkF4 = 2;
    }
    else
    {
        (obj)->unkF4 = 1;
    }
    for (i = 1; (u8)i <= 0x2d; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    state = *(int*)&(obj)->extra;
    ((Dim2lavacontrolState*)state)->countdown = (s8) * (s16*)(param2 + 0x1a);
    ((Dim2lavacontrolState*)state)->countdownSave = *(u8*)&((Dim2lavacontrolState*)state)->countdown;
    if (mainGetBit(((Dim2lavacontrolPlacement*)param2)->gameBit) != 0)
    {
        gameBitState = 1;
    }
    else
    {
        gameBitState = 0;
    }
    ((Dim2lavacontrolState*)state)->flags = (s8)(*(u8*)&((Dim2lavacontrolState*)state)->flags | gameBitState);
    ((Dim2lavacontrolState*)state)->musicTrack = 0xd7;
    ((Dim2lavacontrolState*)state)->phase = DIM2LAVACONTROL_PHASE_WAIT;
    if ((((Dim2lavacontrolState*)state)->flags & 1) != 0)
    {
        *(u8*)&((Dim2lavacontrolState*)state)->countdown = 0;
        ((Dim2lavacontrolState*)state)->sfxLevel = lbl_803DBF28[0];
        fn_8004C1E4(lbl_803DBF28[0], lbl_803E4B90);
    }
    else
    {
        *(u8*)&((Dim2lavacontrolState*)state)->countdown = 3;
        ((Dim2lavacontrolState*)state)->sfxLevel = lbl_803DBF28[3];
        fn_8004C1E4(lbl_803DBF28[3], lbl_803E4B90);
    }
    Music_Trigger(MUSICTRIG_WLC_Corridors, 1);
    envFxActFn_800887f8(0);
}

ObjectDescriptor12 gDIM2LavaControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2lavacontrol_init,
    (ObjectDescriptorCallback)dim2lavacontrol_update,
    0,
    (ObjectDescriptorCallback)dim2lavacontrol_render,
    (ObjectDescriptorCallback)dim2lavacontrol_free,
    0,
    (ObjectDescriptorExtraSizeCallback)dim2lavacontrol_getExtraSize,
    (ObjectDescriptorCallback)dim2lavacontrol_setScale,
    0,
};
