#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"

typedef union VFPLevelControlLatch
{
    u8 raw[8];

    struct
    {
        u8 pad00[4];
        u8 sequenceStep;
        u8 pad05[3];
    } fields;
} VFPLevelControlLatch;

typedef struct VFPLevelControlState
{
    u8 pad00[2];
    s16 cueTimers[6];
    s16 areaMode;
    u8 pad10[4];
    VFPLevelControlLatch latch;
} VFPLevelControlState;

typedef struct VFPLevelControlSetup
{
    u8 pad00[0x1a];
    s16 areaMode;
} VFPLevelControlSetup;

extern int coordsToMapCell(f32 x, f32 z);
extern void SCGameBitLatch_Update(void* latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void skyFn_80088e54(int mode, f32 brightness);
extern f32 lbl_803E6060;

int vfplevelcontrol_getExtraSize(void) { return 0x1c; }

int vfplevelcontrol_getObjectTypeId(void) { return 0x0; }

void vfplevelcontrol_render(void)
{
}

void vfplevelcontrol_hitDetect(void)
{
}

void fn_801F9804(int obj);

void vfplevelcontrol_update(int obj)
{
    VFPLevelControlState* state = ((GameObject*)obj)->extra;
    int player = (int)Obj_GetPlayerObject();
    u8 mapEventState;

    if (((GameObject*)obj)->unkF4 == 0 && GameBit_Get(0xef6) == 0u)
    {
        if (GameBit_Get(0xd72) != 0u)
        {
            getEnvfxActImmediately(obj, obj, 0x10c, 0);
            getEnvfxActImmediately(obj, obj, 0x10d, 0);
            getEnvfxActImmediately(obj, obj, 0x10e, 0);
            skyFn_80088e54(1, lbl_803E6060);
            GameBit_Set(0xd72, 0);
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
            lbl_803DC148 -= (s16)(int)
            timeDelta;
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
            lbl_803DC148 -= (s16)(int)
            timeDelta;
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
            lbl_803DC148 -= (s16)(int)
            timeDelta;
            if (lbl_803DC148 <= 0)
            {
                lbl_803DC148 = 0;
            }
        }
        Obj_GetPlayerObject();
        break;
    }

    SCGameBitLatch_Update(state->latch.raw, 1, -1, -1, 0xdcf, 0xe1);
    SCGameBitLatch_Update(state->latch.raw, 2, -1, -1, 0xdcf, 0x96);
}

void vfplevelcontrol_release(void)
{
}

void vfplevelcontrol_initialise(void)
{
    extern undefined4 ObjGroup_AddObject();
    lbl_803DC148 = 0x82;
}

void vfplevelcontrol_free(int obj)
{
    extern undefined8 ObjGroup_RemoveObject();
    timeOfDayFn_80055000();
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xe1, 0);
}

void vfplevelcontrol_init(int* obj, u8* init)
{
    extern undefined4 ObjGroup_AddObject();
    VFPLevelControlState* state = ((GameObject*)obj)->extra;
    VFPLevelControlSetup* setup = (VFPLevelControlSetup*)init;
    ObjGroup_AddObject(obj, 9);
    state->cueTimers[0] = 0;
    state->cueTimers[1] = 0;
    state->cueTimers[2] = 0;
    state->cueTimers[3] = 0;
    state->cueTimers[4] = 0;
    state->cueTimers[5] = 0;
    state->areaMode = 1;
    if (setup->areaMode != 0 && setup->areaMode <= 2)
    {
        state->areaMode = setup->areaMode;
    }
    lbl_803DC148 = 0x82;
    (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    state->cueTimers[4] = 0;
    state->cueTimers[5] = 0;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    timeOfDayFn_80055038();
    GameBit_Set(0xdcf, 1);
    unlockLevel(0, 0, 1);
    if ((u32)GameBit_Get(0xe1b) != 0)
    {
        state->latch.fields.sequenceStep = 4;
    }
    else
    {
        GameBit_Set(0xe1a, 0);
        GameBit_Set(0xe19, 0);
        GameBit_Set(0xe17, 0);
        GameBit_Set(0xe18, 0);
    }
}

void fn_801F9804(int obj)
{
    s16* p;
    VFPLevelControlState* state = ((GameObject*)obj)->extra;
    s16 bits[4];
    s16 i;

    if (state->latch.fields.sequenceStep < 4)
    {
        bits[0] = GameBit_Get(0xe1a);
        bits[1] = GameBit_Get(0xe19);
        bits[2] = GameBit_Get(0xe17);
        bits[3] = GameBit_Get(0xe18);
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
                        GameBit_Set(0xe1b, 1);
                    }
                }
            }
            else if (*p != 0)
            {
                state->latch.fields.sequenceStep = 0;
                GameBit_Set(0xe1a, 0);
                GameBit_Set(0xe19, 0);
                GameBit_Set(0xe17, 0);
                GameBit_Set(0xe18, 0);
                break;
            }
            p++;
        }
    }
}
