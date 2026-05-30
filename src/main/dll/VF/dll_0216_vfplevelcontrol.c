#include "main/dll/VF/vf_shared.h"
#include "main/mapEventTypes.h"

typedef union VFPLevelControlLatch {
    u8 raw[8];
    struct {
        u8 pad00[4];
        u8 sequenceStep;
        u8 pad05[3];
    } fields;
} VFPLevelControlLatch;

typedef struct VFPLevelControlState {
    u8 pad00[2];
    s16 cueTimers[6];
    s16 areaMode;
    u8 pad10[4];
    VFPLevelControlLatch latch;
} VFPLevelControlState;

typedef struct VFPLevelControlSetup {
    u8 pad00[0x1a];
    s16 areaMode;
} VFPLevelControlSetup;

int vfplevelcontrol_getExtraSize(void) { return 0x1c; }

int vfplevelcontrol_getObjectTypeId(void) { return 0x0; }

void vfplevelcontrol_render(void) {}

void vfplevelcontrol_hitDetect(void) {}

extern int coordsToMapCell(f32 x, f32 z);
extern void SCGameBitLatch_Update(void *latch, int mask, int clearIfSetBit, int clearIfClearBit,
                                  int latchBit, int musicId);
extern void skyFn_80088e54(int mode, f32 brightness);
extern f32 lbl_803E6060;

void fn_801F9804(int obj);

static void vfplevelcontrol_tickGlobalTimer(void) {
    if (lbl_803DC148 != 0) {
        lbl_803DC148 -= (s16)(int)timeDelta;
        if (lbl_803DC148 <= 0) {
            lbl_803DC148 = 0;
        }
    }
}

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_update(int obj) {
    VFPLevelControlState *state = *(VFPLevelControlState **)((char *)obj + 0xb8);
    int player = (int)Obj_GetPlayerObject();
    u8 mapEventState;

    if (*(int *)((char *)obj + 0xf4) == 0 && GameBit_Get(0xef6) == 0) {
        if (GameBit_Get(0xd72) != 0) {
            getEnvfxActImmediately(obj, obj, 0x10c, 0);
            getEnvfxActImmediately(obj, obj, 0x10d, 0);
            getEnvfxActImmediately(obj, obj, 0x10e, 0);
            skyFn_80088e54(1, lbl_803E6060);
            GameBit_Set(0xd72, 0);
        }
        *(int *)((char *)obj + 0xf4) = 1;
    }

    coordsToMapCell(*(f32 *)(player + 0xc), *(f32 *)(player + 0x14));
    mapEventState =
        ((MapEventInterface *)*gMapEventInterface)->getMode((s8)*(u8 *)((char *)obj + 0xac));
    switch (mapEventState) {
    case 1:
        vfplevelcontrol_tickGlobalTimer();
        Obj_GetPlayerObject();
        if (GameBit_Get(0x4ec) == 0 && GameBit_Get(0x9b1) != 0 &&
            GameBit_Get(0x9b2) != 0) {
            GameBit_Set(0x4ec, 1);
        }
        if (GameBit_Get(0xd6d) != 0 && GameBit_Get(0xd6e) != 0 &&
            GameBit_Get(0xd6f) != 0 && GameBit_Get(0xd70) != 0) {
            GameBit_Set(0xcfb, 1);
        }
        break;
    case 2:
        vfplevelcontrol_tickGlobalTimer();
        fn_801F9804(obj);
        break;
    case 3:
        vfplevelcontrol_tickGlobalTimer();
        Obj_GetPlayerObject();
        break;
    }

    SCGameBitLatch_Update(state->latch.raw, 1, -1, -1, 0xdcf, 0xe1);
    SCGameBitLatch_Update(state->latch.raw, 2, -1, -1, 0xdcf, 0x96);
}
#pragma scheduling reset
#pragma peephole reset

void vfplevelcontrol_release(void) {}

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_initialise(void) {
    lbl_803DC148 = 0x82;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_free(int obj) {
    timeOfDayFn_80055000();
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xe1, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_init(int *obj, u8 *init) {
    VFPLevelControlState *state = *(VFPLevelControlState **)((char *)obj + 0xb8);
    VFPLevelControlSetup *setup = (VFPLevelControlSetup *)init;
    ObjGroup_AddObject(obj, 9);
    state->cueTimers[0] = 0;
    state->cueTimers[1] = 0;
    state->cueTimers[2] = 0;
    state->cueTimers[3] = 0;
    state->cueTimers[4] = 0;
    state->cueTimers[5] = 0;
    state->areaMode = 1;
    if (setup->areaMode != 0 && setup->areaMode <= 2) {
        state->areaMode = setup->areaMode;
    }
    lbl_803DC148 = 0x82;
    ((MapEventInterface *)*gMapEventInterface)->getMode((s8)*(u8 *)((char *)obj + 0xac));
    state->cueTimers[4] = 0;
    state->cueTimers[5] = 0;
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    timeOfDayFn_80055038();
    GameBit_Set(0xdcf, 1);
    unlockLevel(0, 0, 1);
    if ((u32)GameBit_Get(0xe1b) != 0) {
        state->latch.fields.sequenceStep = 4;
    } else {
        GameBit_Set(0xe1a, 0);
        GameBit_Set(0xe19, 0);
        GameBit_Set(0xe17, 0);
        GameBit_Set(0xe18, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_801F9804(int obj) {
    VFPLevelControlState *state = *(VFPLevelControlState **)((char *)obj + 0xb8);
    s16 bits[4];
    s16 *p;
    int i;

    if (state->latch.fields.sequenceStep < 4) {
        bits[0] = GameBit_Get(0xe1a);
        bits[1] = GameBit_Get(0xe19);
        bits[2] = GameBit_Get(0xe17);
        bits[3] = GameBit_Get(0xe18);
        p = &bits[state->latch.fields.sequenceStep];
        for (i = state->latch.fields.sequenceStep; i < 4; i++) {
            if (i == state->latch.fields.sequenceStep) {
                if (*p != 0) {
                    state->latch.fields.sequenceStep = state->latch.fields.sequenceStep + 1;
                    if (state->latch.fields.sequenceStep == 4) {
                        GameBit_Set(0xe1b, 1);
                    }
                }
            } else if (*p != 0) {
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
#pragma scheduling reset
#pragma peephole reset
