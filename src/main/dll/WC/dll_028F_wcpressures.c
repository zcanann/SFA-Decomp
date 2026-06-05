#include "main/dll/dll_80220608_shared.h"

#include "main/audio/sfx_ids.h"

#define WCPRESSURES_EXTRA_SIZE 0x7c
#define WCPRESSURES_TRACKED_COUNT 10
#define WCPRESSURES_OBJECT_GROUP 0x31
#define WCPRESSURES_RENDER_TYPE_BASE 0x400
#define WCPRESSURES_RENDER_TYPE_SHIFT 0xb

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

#define WCPRESSURES_HITLIST_OFFSET 0x58
#define WCPRESSURES_HITLIST_OBJECTS_OFFSET 0x100
#define WCPRESSURES_HITLIST_COUNT_OFFSET 0x10f

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

#pragma peephole on
#pragma scheduling on
int wcpressures_getExtraSize(void) { return WCPRESSURES_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcpressures_tileStateCallback(int obj, int unused, int callbackData)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);
    u8 i;

    if (*(u8 *)(callbackData + 0x80) == 1) {
        for (i = 0; i < 10; i++) {
            if (((void **)state)[i + 1] != NULL) {
                *(f32 *)(state + 0x2c + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0xc);
                *(f32 *)(state + 0x30 + i * 8) = *(f32 *)(((int *)state)[i + 1] + 0x14);
            }
        }
        *(u8 *)(callbackData + 0x80) = 0;
    } else if (*(u8 *)(callbackData + 0x80) == 2) {
        for (i = 0; i < 10; i++) {
            *(int *)(state + 4 + i * 4) = 0;
        }
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 8);
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
        *(f32 *)(obj + 0x14) = *(f32 *)(setup + 0x10);
        GameBit_Set(*(s16 *)(setup + 0x1a), 0);
        *(u8 *)(callbackData + 0x80) = 0;
    }

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcpressures_getObjectTypeId(int obj)
{
    int modelIndex = *(u8 *)(*(int *)(obj + 0x4c) + WCPRESSURES_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55);

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
    int r4c = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int i;
    int j;
    f32 thr;

    if (*(s16 *)(r4c + WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET) > 0 &&
        (u32)GameBit_Get(*(s16 *)(r4c + WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET)) == 0) {
        fn_80137948(sWCPressuresActivateFormat, *(s16 *)(r4c + WCPRESSURES_SETUP_ACTIVATE_BIT_OFFSET));
        return;
    }
    {
        int n = WCPRESSURES_STATE_TIMER(state) - 1;
        WCPRESSURES_STATE_TIMER(state) = n;
        if ((s8)n < 0)
            WCPRESSURES_STATE_TIMER(state) = 0;
    }
    if ((s8)*(u8 *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET) > 0) {
        for (i = 0;
             i < (s8)*(u8 *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) + WCPRESSURES_HITLIST_COUNT_OFFSET);
             i++) {
            int ent = *(int *)(*(int *)(obj + WCPRESSURES_HITLIST_OFFSET) +
                               (i * 4 + WCPRESSURES_HITLIST_OBJECTS_OFFSET));
            if (*(f32 *)(ent + 0x10) - *(f32 *)(obj + 0x10) >
                (f32)(u32) * (u8 *)(r4c + WCPRESSURES_SETUP_TRIGGER_HEIGHT_OFFSET)) {
                int s2 = *(int *)(obj + 0xb8);
                int slot;

                for (j = 0; (void *)WCPRESSURES_SLOT_OBJECT(s2, j) != NULL ||
                            (u8)j == WCPRESSURES_TRACKED_COUNT - 1;
                     j++)
                    ;
                slot = (u8)j;
                WCPRESSURES_SLOT_OBJECT(s2, slot) = ent;
                WCPRESSURES_SLOT_X(s2, slot) = *(f32 *)(ent + 0xc);
                WCPRESSURES_SLOT_Z(s2, slot) = *(f32 *)(ent + 0x14);
            }
        }
    }
    {
        int s2 = *(int *)(obj + 0xb8);
        int found = 0;

        for (j = 0; (u8)j < WCPRESSURES_TRACKED_COUNT; j++) {
            int slot = (u8)j;
            int val = WCPRESSURES_SLOT_OBJECT(s2, slot);
            if ((u32)val != 0) {
                if (WCPRESSURES_SLOT_X(s2, slot) == *(f32 *)(val + 0xc) &&
                    WCPRESSURES_SLOT_Z(s2, slot) == *(f32 *)(val + 0x14)) {
                    found = 1;
                } else {
                    WCPRESSURES_SLOT_OBJECT(s2, slot) = 0;
                }
            }
        }
        if (found)
            WCPRESSURES_STATE_TIMER(state) = WCPRESSURES_FOUND_TIMER;
    }
    thr = *(f32 *)(r4c + 0xc) - (f32)(u32) * (u8 *)(r4c + WCPRESSURES_SETUP_PRESS_DEPTH_OFFSET);
    switch (WCPRESSURES_STATE_MODE_BYTE(state)) {
    case WCPRESSURES_MODE_RAISED:
        if (WCPRESSURES_STATE_TIMER(state) != 0 && *(f32 *)(obj + 0x10) >= thr) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            WCPRESSURES_STATE_MODE_BYTE(state) = WCPRESSURES_MODE_LOWERING;
        }
        break;
    case WCPRESSURES_MODE_RISING:
        *(f32 *)(obj + 0x10) = lbl_803E6E04 * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) > *(f32 *)(r4c + 0xc)) {
            *(f32 *)(obj + 0x10) = *(f32 *)(r4c + 0xc);
            WCPRESSURES_STATE_MODE_BYTE(state) = WCPRESSURES_MODE_RAISED;
        }
        break;
    case WCPRESSURES_MODE_PRESSED:
        if ((u32)GameBit_Get(*(s16 *)(r4c + WCPRESSURES_SETUP_SOLVED_BIT_OFFSET)) == 0) {
            Sfx_PlayFromObject(obj, SFXsc_lockon2_on);
            WCPRESSURES_STATE_MODE_BYTE(state) = WCPRESSURES_MODE_RISING;
        }
        break;
    case WCPRESSURES_MODE_LOWERING:
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E6E04 * timeDelta;
        if (*(f32 *)(obj + 0x10) < thr) {
            GameBit_Set(*(s16 *)(r4c + WCPRESSURES_SETUP_SOLVED_BIT_OFFSET), 1);
            WCPRESSURES_STATE_MODE_BYTE(state) = WCPRESSURES_MODE_PRESSED;
            *(f32 *)(obj + 0x10) = thr;
        }
        break;
    }
    {
        int *tex = objFindTexture(obj, 0, 0);
        if (tex != 0) {
            *tex = WCPRESSURES_STATE_MODE_BYTE(state) == WCPRESSURES_MODE_PRESSED ? WCPRESSURES_TEXTURE_PRESSED
                                                                                  : 0;
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
    u8 *state = *(u8 **)(obj + 0xb8);
    s16 objType;
    u16 objFlags;
    s8 modelIndex;
    int i;

    objType = (s16)(setup[0x18] << 8);
    *(s16 *)obj = objType;
    objFlags = *(u16 *)(obj + 0xb0) | 0x6000;
    *(u16 *)(obj + 0xb0) = objFlags;
    modelIndex = (s8)setup[0x19];
    *(s8 *)(obj + 0xad) = modelIndex;
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1a)) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc) - (f32)*(u8 *)(setup + 0x1c);
        state[0] = 0x1e;
        state[1] = 2;
    }

    ObjGroup_AddObject((int)obj, 0x31);
    for (i = 0; i < 10; i++) {
        *(int *)(state + 4 + i * 4) = 0;
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
