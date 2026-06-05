#include "main/dll/dll_80220608_shared.h"

#include "main/audio/sfx_ids.h"

#define WCPRESSURES_OBJECT_DEF_ID 0x0128
#define WCPRESSURES_DLL_ID 0x028f
#define WCPRESSURES_CLASS_ID 0x0052

#define WCPRESSURES_EXTRA_SIZE 0x7c
#define WCPRESSURES_TRACKED_COUNT 10
#define WCPRESSURES_OBJECT_GROUP 0x31
#define WCPRESSURES_OBJECT_FLAGS_INIT 0x6000
#define WCPRESSURES_RENDER_TYPE_BASE 0x400
#define WCPRESSURES_RENDER_TYPE_SHIFT 0xb

#define WCPRESSURES_SETUP_POS_X_OFFSET 0x08
#define WCPRESSURES_SETUP_POS_Y_OFFSET 0x0c
#define WCPRESSURES_SETUP_POS_Z_OFFSET 0x10
#define WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET 0x18
#define WCPRESSURES_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCPRESSURES_SETUP_SOLVED_BIT_OFFSET 0x1a
#define WCPRESSURES_SETUP_PRESS_DEPTH_OFFSET 0x1c
#define WCPRESSURES_SETUP_TRIGGER_HEIGHT_OFFSET 0x1d
#define WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET 0x20

#define WCPRESSURES_STATE_PRESS_TIMER 0x00
#define WCPRESSURES_STATE_MODE 0x01
#define WCPRESSURES_STATE_OBJECTS 0x04
#define WCPRESSURES_STATE_SAVED_X 0x2c
#define WCPRESSURES_STATE_SAVED_Z 0x30
#define WCPRESSURES_STATE_SAVED_POS_STRIDE 8

#define WCPRESSURES_MODE_RAISED 0
#define WCPRESSURES_MODE_RISING 1
#define WCPRESSURES_MODE_PRESSED 2
#define WCPRESSURES_MODE_LOWERING 3

#define WCPRESSURES_FOUND_TIMER 5
#define WCPRESSURES_SOLVED_TIMER 0x1e

#define WCPRESSURES_OBJECT_SETUP_OFFSET 0x4c
#define WCPRESSURES_OBJECT_MODEL_DATA_OFFSET 0x50
#define WCPRESSURES_OBJECT_Y_OFFSET 0x10
#define WCPRESSURES_OBJECT_Z_OFFSET 0x14
#define WCPRESSURES_OBJECT_MODEL_INDEX_OFFSET 0xad
#define WCPRESSURES_OBJECT_FLAGS_OFFSET 0xb0
#define WCPRESSURES_OBJECT_STATE_OFFSET 0xb8
#define WCPRESSURES_OBJECT_TILE_CALLBACK_OFFSET 0xbc
#define WCPRESSURES_MODEL_COUNT_OFFSET 0x55

#define WCPRESSURES_CALLBACK_COMMAND_OFFSET 0x80
#define WCPRESSURES_CALLBACK_NONE 0
#define WCPRESSURES_CALLBACK_SNAPSHOT_TILES 1
#define WCPRESSURES_CALLBACK_RESET 2

#define WCPRESSURES_HITLIST_OFFSET 0x58
#define WCPRESSURES_HITLIST_OBJECTS_OFFSET 0x100
#define WCPRESSURES_HITLIST_COUNT_OFFSET 0x10f

#define WCPRESSURES_TEXTURE_DEFAULT 0
#define WCPRESSURES_TEXTURE_PRESSED 1
#define WCPRESSURES_TEXTURE_SHIFT 8

#define WCPRESSURES_STATE_TIMER(state) (*(s8 *)((u8 *)(state) + WCPRESSURES_STATE_PRESS_TIMER))
#define WCPRESSURES_STATE_MODE_BYTE(state) (*(s8 *)((u8 *)(state) + WCPRESSURES_STATE_MODE))
#define WCPRESSURES_SLOT_OBJECT(state, slot) \
    (*(int *)((u8 *)(state) + WCPRESSURES_STATE_OBJECTS + (u8)(slot) * 4))
#define WCPRESSURES_SLOT_X(state, slot) \
    (*(f32 *)((u8 *)(state) + WCPRESSURES_STATE_SAVED_X + (u8)(slot) * WCPRESSURES_STATE_SAVED_POS_STRIDE))
#define WCPRESSURES_SLOT_Z(state, slot) \
    (*(f32 *)((u8 *)(state) + WCPRESSURES_STATE_SAVED_Z + (u8)(slot) * WCPRESSURES_STATE_SAVED_POS_STRIDE))

typedef struct WCPressuresSetup {
    u8 pad00[WCPRESSURES_SETUP_POS_X_OFFSET];
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET - 0x14];
    u8 objectTypeHi;
    u8 modelIndex;
    s16 solvedBit;
    u8 pressDepth;
    u8 triggerHeight;
    u8 pad1E[WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET - 0x1e];
    s16 activateBit;
} WCPressuresSetup;

typedef struct WCPressuresSavedPos {
    f32 x;
    f32 z;
} WCPressuresSavedPos;

typedef struct WCPressuresState {
    s8 pressTimer;
    s8 mode;
    u8 pad02[2];
    int objects[WCPRESSURES_TRACKED_COUNT];
    WCPressuresSavedPos savedPos[WCPRESSURES_TRACKED_COUNT];
} WCPressuresState;

STATIC_ASSERT(sizeof(WCPressuresState) == WCPRESSURES_EXTRA_SIZE);
STATIC_ASSERT(offsetof(WCPressuresState, pressTimer) == WCPRESSURES_STATE_PRESS_TIMER);
STATIC_ASSERT(offsetof(WCPressuresState, mode) == WCPRESSURES_STATE_MODE);
STATIC_ASSERT(offsetof(WCPressuresState, objects) == WCPRESSURES_STATE_OBJECTS);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].x) == WCPRESSURES_STATE_SAVED_X);
STATIC_ASSERT(offsetof(WCPressuresState, savedPos[0].z) == WCPRESSURES_STATE_SAVED_Z);
STATIC_ASSERT(offsetof(WCPressuresSetup, x) == WCPRESSURES_SETUP_POS_X_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, y) == WCPRESSURES_SETUP_POS_Y_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, z) == WCPRESSURES_SETUP_POS_Z_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, objectTypeHi) == WCPRESSURES_SETUP_OBJECT_TYPE_HI_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, modelIndex) == WCPRESSURES_SETUP_MODEL_INDEX_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, solvedBit) == WCPRESSURES_SETUP_SOLVED_BIT_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, pressDepth) == WCPRESSURES_SETUP_PRESS_DEPTH_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, triggerHeight) == WCPRESSURES_SETUP_TRIGGER_HEIGHT_OFFSET);
STATIC_ASSERT(offsetof(WCPressuresSetup, activateBit) == WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET);

#pragma peephole on
#pragma scheduling on
int wcpressures_getExtraSize(void) { return WCPRESSURES_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcpressures_tileStateCallback(int obj, int unused, int callbackData)
{
    WCPressuresState *state = *(WCPressuresState **)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
    WCPressuresSetup *setup = *(WCPressuresSetup **)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
    u8 i;

    if (*(u8 *)(callbackData + WCPRESSURES_CALLBACK_COMMAND_OFFSET) == WCPRESSURES_CALLBACK_SNAPSHOT_TILES) {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++) {
            if ((void *)state->objects[i] != NULL) {
                state->savedPos[i].x = *(f32 *)(state->objects[i] + 0xc);
                state->savedPos[i].z = *(f32 *)(state->objects[i] + WCPRESSURES_OBJECT_Z_OFFSET);
            }
        }
        *(u8 *)(callbackData + WCPRESSURES_CALLBACK_COMMAND_OFFSET) = WCPRESSURES_CALLBACK_NONE;
    } else if (*(u8 *)(callbackData + WCPRESSURES_CALLBACK_COMMAND_OFFSET) == WCPRESSURES_CALLBACK_RESET) {
        for (i = 0; i < WCPRESSURES_TRACKED_COUNT; i++) {
            state->objects[i] = 0;
        }
        *(f32 *)(obj + WCPRESSURES_OBJECT_Z_OFFSET) = setup->x;
        *(f32 *)(obj + WCPRESSURES_OBJECT_Y_OFFSET) = setup->y;
        *(f32 *)(obj + WCPRESSURES_OBJECT_Z_OFFSET) = setup->z;
        GameBit_Set(setup->solvedBit, 0);
        *(u8 *)(callbackData + WCPRESSURES_CALLBACK_COMMAND_OFFSET) = WCPRESSURES_CALLBACK_NONE;
    }

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcpressures_getObjectTypeId(int obj)
{
    int modelIndex = *(u8 *)(*(int *)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET) +
                             WCPRESSURES_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + WCPRESSURES_OBJECT_MODEL_DATA_OFFSET) +
                                  WCPRESSURES_MODEL_COUNT_OFFSET);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCPRESSURES_RENDER_TYPE_SHIFT) | WCPRESSURES_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcpressures_free(int obj) { ObjGroup_RemoveObject(obj, WCPRESSURES_OBJECT_GROUP); }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcpressures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E00);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpressures_update(int obj)
{
    WCPressuresSetup *setup = *(WCPressuresSetup **)(obj + WCPRESSURES_OBJECT_SETUP_OFFSET);
    WCPressuresState *state = *(WCPressuresState **)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
    int i;
    int j;
    f32 thr;

    if (setup->activateBit > 0 &&
        (u32)GameBit_Get(setup->activateBit) == 0) {
        fn_80137948(sWCPressuresActivateFormat, setup->activateBit);
        return;
    }
    {
        int n = state->pressTimer - 1;
        state->pressTimer = n;
        if ((s8)n < 0)
            state->pressTimer = 0;
    }
    if ((s8)*(u8 *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET) > 0) {
        for (i = 0;
             i < (s8)*(u8 *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET);
             i++) {
            int ent = *(int *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) +
                               (i * 4 + WCPRESSURES_HITLIST_OBJECTS_OFFSET));
            if (*(f32 *)(ent + 0x10) - *(f32 *)(obj + 0x10) >
                (f32)(u32)setup->triggerHeight) {
                WCPressuresState *s2 = *(WCPressuresState **)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
                int slot;

                for (j = 0; (void *)s2->objects[(u8)j] != NULL ||
                            (u8)j == WCPRESSURES_TRACKED_COUNT - 1;
                     j++)
                    ;
                slot = (u8)j;
                s2->objects[slot] = ent;
                s2->savedPos[slot].x = *(f32 *)(ent + 0xc);
                s2->savedPos[slot].z = *(f32 *)(ent + 0x14);
            }
        }
    }
    {
        WCPressuresState *s2 = *(WCPressuresState **)(obj + WCPRESSURES_OBJECT_STATE_OFFSET);
        int found = 0;

        for (j = 0; (u8)j < WCPRESSURES_TRACKED_COUNT; j++) {
            int slot = (u8)j;
            int val = s2->objects[slot];
            if ((u32)val != 0) {
                if (s2->savedPos[slot].x == *(f32 *)(val + 0xc) &&
                    s2->savedPos[slot].z == *(f32 *)(val + 0x14)) {
                    found = 1;
                } else {
                    s2->objects[slot] = 0;
                }
            }
        }
        if (found)
            state->pressTimer = WCPRESSURES_FOUND_TIMER;
    }
    thr = setup->y - (f32)(u32)setup->pressDepth;
    switch (state->mode) {
    case WCPRESSURES_MODE_RAISED:
        if (state->pressTimer != 0 && *(f32 *)(obj + 0x10) >= thr) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            state->mode = WCPRESSURES_MODE_LOWERING;
        }
        break;
    case WCPRESSURES_MODE_RISING:
        *(f32 *)(obj + 0x10) = lbl_803E6E04 * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) > setup->y) {
            *(f32 *)(obj + 0x10) = setup->y;
            state->mode = WCPRESSURES_MODE_RAISED;
        }
        break;
    case WCPRESSURES_MODE_PRESSED:
        if ((u32)GameBit_Get(setup->solvedBit) == 0) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            state->mode = WCPRESSURES_MODE_RISING;
        }
        break;
    case WCPRESSURES_MODE_LOWERING:
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E6E04 * timeDelta;
        if (*(f32 *)(obj + 0x10) < thr) {
            GameBit_Set(setup->solvedBit, 1);
            state->mode = WCPRESSURES_MODE_PRESSED;
            *(f32 *)(obj + 0x10) = thr;
        }
        break;
    }
    {
        int *tex = objFindTexture(obj, WCPRESSURES_TEXTURE_DEFAULT, WCPRESSURES_TEXTURE_DEFAULT);
        if (tex != 0) {
            *tex = state->mode == WCPRESSURES_MODE_PRESSED ? WCPRESSURES_TEXTURE_PRESSED
                                                            : WCPRESSURES_TEXTURE_DEFAULT;
            *tex = *tex << WCPRESSURES_TEXTURE_SHIFT;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcpressures_init(u8 *obj, u8 *setup)
{
    WCPressuresState *state = *(WCPressuresState **)(obj + 0xb8);
    WCPressuresSetup *setupData = (WCPressuresSetup *)setup;
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setupData->objectTypeHi << 8);
    *(s16 *)obj = objType;
    objFlags = *(u16 *)(obj + 0xb0) | 0x6000;
    *(u16 *)(obj + 0xb0) = objFlags;
    modelIndex = (s8)setupData->modelIndex;
    *(s8 *)(obj + 0xad) = modelIndex;
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }

    if ((u32)GameBit_Get(setupData->solvedBit) != 0) {
        *(f32 *)(obj + 0x10) = setupData->y - (f32)setupData->pressDepth;
        state->pressTimer = WCPRESSURES_SOLVED_TIMER;
        state->mode = WCPRESSURES_MODE_PRESSED;
    }

    ObjGroup_AddObject((int)obj, 0x31);
    for (i = 0; i < 10; i++) {
        state->objects[i] = 0;
    }
    *(void **)(obj + 0xbc) = wcpressures_tileStateCallback;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcpressures_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
