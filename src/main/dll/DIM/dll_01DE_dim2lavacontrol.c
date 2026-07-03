/* DLL 0x1DE — DIM2 Lava Control: manages the DIM2 lava-rise sequence —
 * triggers env-fx transitions, drives music track changes based on player
 * carry state, and maintains the countdown-armed SCGameBitLatch triggers. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"
#include "main/dll/player_objects.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void Music_Trigger(int id, int arg);
extern void objRenderFn_8003b8f4(f32);

extern int getSaveGameLoadStatus(void);
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/music_trigger_ids.h"

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

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E4B90;
extern void fn_8004C1E4(int sfxId, f32 vol);
extern void timeOfDayFn_80055000(void);
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4;
extern void envFxActFn_800887f8(u8 value);
extern u8 lbl_803DBF28[8];
extern void SCGameBitLatch_UpdateInverted(void* p, int mask, int a, int b, int e1, int e2);

int dim2lavacontrol_getExtraSize(void) { return 0x10; }

#pragma scheduling off
#pragma peephole off
void dim2lavacontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B90);
}

void dim2lavacontrol_setScale(void* obj)
{
    void* sub = ((GameObject*)obj)->extra;
    if (((s32)((Dim2lavacontrolState*)sub)->flags & 1) == 0)
    {
        void* p = *(void**)&((GameObject*)obj)->anim.placementData;
        if ((s32)((Dim2lavacontrolState*)sub)->countdown > 0)
        {
            ((Dim2lavacontrolState*)sub)->countdown -= 1;
            if (((Dim2lavacontrolState*)sub)->countdown == 0)
            {
                ((Dim2lavacontrolState*)sub)->flags = (s8)(*(u8*)&((Dim2lavacontrolState*)sub)->flags | 1);
                GameBit_Set(((Dim2lavacontrolPlacement*)p)->gameBit, 1);
            }
        }
    }
}

void dim2lavacontrol_free(void)
{
    fn_8004C1E4(0xC0, lbl_803E4B90);
    Music_Trigger(MUSICTRIG_PU3_Adventure_c4, 0);
    timeOfDayFn_80055000();
}

void dim2lavacontrol_init(int obj, int param2)
{
    extern void gameBitFn_800ea2e0(int i);
    int state;
    int i;
    int g;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    for (i = 1; (u8)i <= 0x2d; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    state = *(int*)&((GameObject*)obj)->extra;
    ((Dim2lavacontrolState*)state)->countdown = (s8) * (s16*)(param2 + 0x1a);
    ((Dim2lavacontrolState*)state)->countdownSave = *(u8*)&((Dim2lavacontrolState*)state)->countdown;
    if (GameBit_Get(((Dim2lavacontrolPlacement*)param2)->gameBit) != 0)
    {
        g = 1;
    }
    else
    {
        g = 0;
    }
    ((Dim2lavacontrolState*)state)->flags = (s8)(*(u8*)&((Dim2lavacontrolState*)state)->flags | g);
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

#pragma opt_common_subs off
void dim2lavacontrol_update(int obj)
{
    extern void SCGameBitLatch_Update(void* p, int mask, int a, int b, int e1, int e2);
    int diff;
    int heldObj;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->unkF4 == 2)
        {
            getEnvfxActImmediately(0, 0, 0x163, 0);
            getEnvfxActImmediately(0, 0, 0x166, 0);
            getEnvfxActImmediately(0, 0, 0x165, 0);
            getEnvfxActImmediately(0, 0, 0x164, 0);
        }
        else
        {
            getEnvfxAct(0, 0, 0x163, 0);
            getEnvfxAct(0, 0, 0x166, 0);
            getEnvfxAct(0, 0, 0x165, 0);
            getEnvfxAct(0, 0, 0x164, 0);
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    obj = *(int*)&((GameObject*)obj)->extra;
    switch (((Dim2lavacontrolState*)obj)->phase)
    {
    case DIM2LAVACONTROL_PHASE_WAIT:
        if (GameBit_Get(0xacd) != 0)
        {
            GameBit_Set(0xcc3, 1);
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
    if (Player_GetHeldObject((int)Obj_GetPlayerObject(), &heldObj) != 0)
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
    SCGameBitLatch_Update((char*)obj + 8, 1, -1, -1, 0xd99, 0xde);
    SCGameBitLatch_Update((char*)obj + 8, 2, -1, -1, 0xda5, *(int*)&((GameObject*)obj)->anim.localPosX);
    SCGameBitLatch_Update((char*)obj + 8, 8, -1, -1, 0xf04, 0x96);
    SCGameBitLatch_UpdateInverted((char*)obj + 8, 0x10, -1, -1, 0xf04, 0x2c);
    SCGameBitLatch_Update((char*)obj + 8, 4, -1, -1, 0xcbb, 0xc4);
}
