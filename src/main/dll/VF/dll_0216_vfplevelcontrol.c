/*
 * vfplevelcontrol (DLL 0x216, VFP_LevelControl) - the master controller
 * object for the Volcano Force Point Temple ("VFP") level.
 *
 * It owns the level-wide bookkeeping that has no single visible object:
 *  - a one-shot environment/sky transition on the first update tick
 *    (envfx 0x10c..0x10e + skyFn_80088e54), gated by a global game bit;
 *  - per-map-event-state logic (the map-act value 0..3 returned by the
 *    map-event interface), each state counting down the shared timer
 *    lbl_803DC148 and rolling up groups of progress bits into summary
 *    bits;
 *  - the spell-tablet ordered-sequence puzzle (fn_801F9804), which
 *    requires the four step bits to light in order and grants the
 *    "sequence done" bit when all four are set;
 *  - two music latches driven through SCGameBitLatch_Update.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"

#define VFPLEVELCONTROL_OBJGROUP 9

/* Ordered spell-tablet sequence: the four step bits must light in this
   array order (advanced by fn_801F9804); lighting them out of order
   resets the puzzle. SEQUENCE_DONE is granted once all four are set. */
enum
{
    GAMEBIT_VFP_SEQ_STEP_0 = 0xe1a,
    GAMEBIT_VFP_SEQ_STEP_1 = 0xe19,
    GAMEBIT_VFP_SEQ_STEP_2 = 0xe17,
    GAMEBIT_VFP_SEQ_STEP_3 = 0xe18,
    GAMEBIT_VFP_SEQ_DONE = 0xe1b
};

/* the level's intro environment transition (run once) */
#define GAMEBIT_VFP_INTRO_DONE 0xef6  /* global "intro already played" gate */
#define GAMEBIT_VFP_SKY_PENDING 0xd72 /* request the day sky swap, cleared after */
#define VFP_ENVFX_INTRO_0 0x10c
#define VFP_ENVFX_INTRO_1 0x10d
#define VFP_ENVFX_INTRO_2 0x10e

#define GAMEBIT_VFP_LATCH 0xdcf /* music-latch bit shared by both latches */
#define VFP_MUSIC_A 0xe1
#define VFP_MUSIC_B 0x96

#define VFP_TIMER_INIT 0x82

#define VFPLEVELCONTROL_OBJFLAG_HIDDEN 0x4000
#define VFPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef union VfpLevelControlLatch
{
    u8 raw[8];

    struct
    {
        u8 pad00[4];
        u8 sequenceStep; /* 0x04: index of the next sequence bit to light */
        u8 pad05[3];
    } fields;
} VfpLevelControlLatch;

typedef struct VfpLevelControlState
{
    u8 pad00[2];
    s16 unk02[6];               /* 0x02: cleared at init, never read back */
    s16 areaMode;               /* 0x0E: 1..2, from setup (defaults to 1) */
    u8 pad10[4];
    VfpLevelControlLatch latch; /* 0x14 */
} VfpLevelControlState;

typedef struct VfpLevelControlSetup
{
    u8 pad00[0x1a];
    s16 areaMode; /* 0x1A */
} VfpLevelControlSetup;

STATIC_ASSERT(offsetof(VfpLevelControlState, unk02) == 0x02);
STATIC_ASSERT(offsetof(VfpLevelControlState, areaMode) == 0x0E);
STATIC_ASSERT(offsetof(VfpLevelControlState, latch) == 0x14);
STATIC_ASSERT(sizeof(VfpLevelControlState) == 0x1c);
STATIC_ASSERT(offsetof(VfpLevelControlLatch, fields.sequenceStep) == 0x04);
STATIC_ASSERT(offsetof(VfpLevelControlSetup, areaMode) == 0x1A);

extern int coordsToMapCell(f32 x, f32 z);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void skyFn_80088e54(int mode, f32 brightness);
extern f32 lbl_803E6060;
extern u32 ObjGroup_AddObject();
extern void ObjGroup_RemoveObject(u32 obj, int group);

void fn_801F9804(int obj);

int vfplevelcontrol_getExtraSize(void) { return 0x1c; }

int vfplevelcontrol_getObjectTypeId(void) { return 0x0; }

void vfplevelcontrol_render(void)
{
}

void vfplevelcontrol_hitDetect(void)
{
}

void vfplevelcontrol_update(int obj)
{
    VfpLevelControlState* state = ((GameObject*)obj)->extra;
    int player = (int)Obj_GetPlayerObject();
    u8 mapEventState;

    if (((GameObject*)obj)->unkF4 == 0 && GameBit_Get(GAMEBIT_VFP_INTRO_DONE) == 0u)
    {
        if (GameBit_Get(GAMEBIT_VFP_SKY_PENDING) != 0u)
        {
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_0, 0);
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_1, 0);
            getEnvfxActImmediately(obj, obj, VFP_ENVFX_INTRO_2, 0);
            skyFn_80088e54(1, lbl_803E6060);
            GameBit_Set(GAMEBIT_VFP_SKY_PENDING, 0);
        }
        ((GameObject*)obj)->unkF4 = 1;
    }

    coordsToMapCell(((GameObject*)player)->anim.localPosX, ((GameObject*)player)->anim.localPosZ);
    mapEventState = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    switch (mapEventState)
    {
    case 0:
        break;
    case 1:
        if (lbl_803DC148 != 0)
        {
            lbl_803DC148 -= (s16)(int)timeDelta;
            if (lbl_803DC148 <= 0)
            {
                lbl_803DC148 = 0;
            }
        }
        Obj_GetPlayerObject();
        if (GameBit_Get(0x4ec) == 0u && GameBit_Get(0x9b1) != 0u &&
            GameBit_Get(0x9b2) != 0u)
        {
            GameBit_Set(0x4ec, 1);
        }
        if (GameBit_Get(0xd6d) != 0u && GameBit_Get(0xd6e) != 0u &&
            GameBit_Get(0xd6f) != 0u && GameBit_Get(0xd70) != 0u)
        {
            GameBit_Set(0xcfb, 1);
        }
        break;
    case 2:
        if (lbl_803DC148 != 0)
        {
            lbl_803DC148 -= (s16)(int)timeDelta;
            if (lbl_803DC148 <= 0)
            {
                lbl_803DC148 = 0;
            }
        }
        fn_801F9804(obj);
        break;
    case 3:
        if (lbl_803DC148 != 0)
        {
            lbl_803DC148 -= (s16)(int)timeDelta;
            if (lbl_803DC148 <= 0)
            {
                lbl_803DC148 = 0;
            }
        }
        Obj_GetPlayerObject();
        break;
    }

    SCGameBitLatch_Update(state->latch.raw, 1, -1, -1, GAMEBIT_VFP_LATCH, VFP_MUSIC_A);
    SCGameBitLatch_Update(state->latch.raw, 2, -1, -1, GAMEBIT_VFP_LATCH, VFP_MUSIC_B);
}

void vfplevelcontrol_release(void)
{
}

void vfplevelcontrol_initialise(void)
{
    lbl_803DC148 = VFP_TIMER_INIT;
}

void vfplevelcontrol_free(int obj)
{
    timeOfDayFn_80055000();
    ObjGroup_RemoveObject(obj, VFPLEVELCONTROL_OBJGROUP);
    Music_Trigger(VFP_MUSIC_A, 0);
}

void vfplevelcontrol_init(int* obj, u8* init)
{
    VfpLevelControlState* state = ((GameObject*)obj)->extra;
    VfpLevelControlSetup* setup = (VfpLevelControlSetup*)init;
    ObjGroup_AddObject(obj, VFPLEVELCONTROL_OBJGROUP);
    state->unk02[0] = 0;
    state->unk02[1] = 0;
    state->unk02[2] = 0;
    state->unk02[3] = 0;
    state->unk02[4] = 0;
    state->unk02[5] = 0;
    state->areaMode = 1;
    if (setup->areaMode != 0 && setup->areaMode <= 2)
    {
        state->areaMode = setup->areaMode;
    }
    lbl_803DC148 = VFP_TIMER_INIT;
    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    state->unk02[4] = 0;
    state->unk02[5] = 0;
    ((GameObject*)obj)->objectFlags |= (VFPLEVELCONTROL_OBJFLAG_HIDDEN | VFPLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED);
    timeOfDayFn_80055038();
    GameBit_Set(GAMEBIT_VFP_LATCH, 1);
    unlockLevel(0, 0, 1);
    if ((u32)GameBit_Get(GAMEBIT_VFP_SEQ_DONE) != 0)
    {
        state->latch.fields.sequenceStep = 4;
    }
    else
    {
        GameBit_Set(GAMEBIT_VFP_SEQ_STEP_0, 0);
        GameBit_Set(GAMEBIT_VFP_SEQ_STEP_1, 0);
        GameBit_Set(GAMEBIT_VFP_SEQ_STEP_2, 0);
        GameBit_Set(GAMEBIT_VFP_SEQ_STEP_3, 0);
    }
}

/* Advance the ordered spell-tablet puzzle. The four step bits must be
   set in array order; the next-expected bit advances the step, any
   later bit lighting early resets the whole puzzle. */
void fn_801F9804(int obj)
{
    s16* p;
    VfpLevelControlState* state = ((GameObject*)obj)->extra;
    s16 bits[4];
    s16 i;

    if (state->latch.fields.sequenceStep < 4)
    {
        bits[0] = GameBit_Get(GAMEBIT_VFP_SEQ_STEP_0);
        bits[1] = GameBit_Get(GAMEBIT_VFP_SEQ_STEP_1);
        bits[2] = GameBit_Get(GAMEBIT_VFP_SEQ_STEP_2);
        bits[3] = GameBit_Get(GAMEBIT_VFP_SEQ_STEP_3);
        i = state->latch.fields.sequenceStep;
        p = &bits[i];
        for (; i < 4; i++)
        {
            if (i == state->latch.fields.sequenceStep)
            {
                if (*p != 0)
                {
                    state->latch.fields.sequenceStep++;
                    if (state->latch.fields.sequenceStep == 4)
                    {
                        GameBit_Set(GAMEBIT_VFP_SEQ_DONE, 1);
                    }
                }
            }
            else if (*p != 0)
            {
                state->latch.fields.sequenceStep = 0;
                GameBit_Set(GAMEBIT_VFP_SEQ_STEP_0, 0);
                GameBit_Set(GAMEBIT_VFP_SEQ_STEP_1, 0);
                GameBit_Set(GAMEBIT_VFP_SEQ_STEP_2, 0);
                GameBit_Set(GAMEBIT_VFP_SEQ_STEP_3, 0);
                break;
            }
            p++;
        }
    }
}
