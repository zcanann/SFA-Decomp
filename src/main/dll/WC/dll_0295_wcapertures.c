#include "main/dll/dll_80220608_shared.h"

#define WCAPERTURES_EXTRA_SIZE 8
#define WCAPERTURES_RENDER_TYPE_BASE 0x400
#define WCAPERTURES_RENDER_TYPE_SHIFT 0xb

#define WCAPERTURES_SETUP_TYPE_OFFSET 0x18
#define WCAPERTURES_SETUP_MODEL_INDEX_OFFSET 0x19
#define WCAPERTURES_SETUP_OPEN_BIT_OFFSET 0x1e
#define WCAPERTURES_SETUP_ARM_BIT_OFFSET 0x20

#define WCAPERTURES_STATE_LIGHT 0x00
#define WCAPERTURES_STATE_TARGET_ALPHA 0x04
#define WCAPERTURES_STATE_MODE 0x06
#define WCAPERTURES_STATE_FLAGS 0x07

#define WCAPERTURES_MODE_CLOSED 0
#define WCAPERTURES_MODE_ARMED 1
#define WCAPERTURES_MODE_OPEN 2

#define WCAPERTURES_FLAG_VISIBLE 1
#define WCAPERTURES_INITIAL_ALPHA 1
#define WCAPERTURES_ALPHA_OPAQUE 255
#define WCAPERTURES_ALPHA_STEP_SHIFT 2
#define WCAPERTURES_LIGHT_ENABLE_THRESHOLD 128

#define WCAPERTURES_CALLBACK_COMMANDS_OFFSET 0x81
#define WCAPERTURES_CALLBACK_COMMAND_COUNT_OFFSET 0x8b
#define WCAPERTURES_CALLBACK_ARM 1

#define WCAPERTURES_PARTFX_OPEN 0x805
#define WCAPERTURES_PARTFX_KIND 2
#define WCAPERTURES_PARTFX_INVALID_HANDLE -1

#define WCAPERTURES_CAMERA_MODE 68
#define WCAPERTURES_PLAYER_STATE 33
#define WCAPERTURES_ACCEPT_OBJECT_FLAG 0x800

#define WCAPERTURES_LIGHT_KIND 2
#define WCAPERTURES_LIGHT_BLUE_LO 0x4d
#define WCAPERTURES_LIGHT_BLUE_HI 0x96

#define WCAPERTURES_LIGHT(state) (*(void **)((state) + WCAPERTURES_STATE_LIGHT))
#define WCAPERTURES_TARGET_ALPHA(state) (*(s16 *)((state) + WCAPERTURES_STATE_TARGET_ALPHA))
#define WCAPERTURES_MODE(state) (*(u8 *)((state) + WCAPERTURES_STATE_MODE))
#define WCAPERTURES_FLAGS(state) (*(u8 *)((state) + WCAPERTURES_STATE_FLAGS))

#pragma peephole on
#pragma scheduling on
int wcapertures_getExtraSize(void) { return WCAPERTURES_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcapertures_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + WCAPERTURES_SETUP_MODEL_INDEX_OFFSET);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << WCAPERTURES_RENDER_TYPE_SHIFT) | WCAPERTURES_RENDER_TYPE_BASE;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcapertures_free(int obj)
{
    void *light = WCAPERTURES_LIGHT(*(int *)(obj + 0xb8));

    if (light != NULL) {
        ModelLightStruct_free(light);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    char *state = *(char **)(obj + 0xb8);
    u8 *light;

    if (visible != 0) {
        WCAPERTURES_FLAGS((int)state) |= WCAPERTURES_FLAG_VISIBLE;
    } else {
        WCAPERTURES_FLAGS((int)state) &= ~WCAPERTURES_FLAG_VISIBLE;
    }
    light = WCAPERTURES_LIGHT((int)state);
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0) {
        queueGlowRender(light);
    }
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E2C);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (WCAPERTURES_MODE(state) == WCAPERTURES_MODE_OPEN) {
        f32 col[3];
        s16 ev[2];

        if ((s8)*(u8 *)(obj + 0xad) == 0)
            ev[1] = 1;
        else
            ev[1] = 0;
        col[0] = lbl_803E6E30;
        col[1] = lbl_803E6E34;
        col[2] = lbl_803E6E28;
        (*(void (**)(int, int, void *, int, int, void *))(*gPartfxInterface + 8))(
            obj, WCAPERTURES_PARTFX_OPEN, ev, WCAPERTURES_PARTFX_KIND, WCAPERTURES_PARTFX_INVALID_HANDLE, col);
    }
    if (WCAPERTURES_LIGHT(state) != NULL)
        modelLightStruct_updateGlowAlpha(WCAPERTURES_LIGHT(state));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcapertures_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcapertures_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcapertures_interactCallback(int obj, int p2, int p3)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    for (i = 0; i < *(u8 *)(p3 + WCAPERTURES_CALLBACK_COMMAND_COUNT_OFFSET); i++) {
        if (*(u8 *)(p3 + (i + WCAPERTURES_CALLBACK_COMMANDS_OFFSET)) == WCAPERTURES_CALLBACK_ARM)
            WCAPERTURES_MODE(state) = WCAPERTURES_MODE_ARMED;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_init(int obj, int initData)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(initData + WCAPERTURES_SETUP_TYPE_OFFSET) << 8);
    *(void **)(obj + 0xbc) = (void *)wcapertures_interactCallback;
    *(u8 *)(obj + 0xad) = *(u8 *)(initData + WCAPERTURES_SETUP_MODEL_INDEX_OFFSET);
    if ((s8)*(u8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55))
        *(u8 *)(obj + 0xad) = 0;
    if ((u32)GameBit_Get(*(s16 *)(initData + WCAPERTURES_SETUP_ARM_BIT_OFFSET)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(initData + WCAPERTURES_SETUP_OPEN_BIT_OFFSET)) != 0)
            WCAPERTURES_MODE(state) = WCAPERTURES_MODE_OPEN;
        else
            WCAPERTURES_MODE(state) = WCAPERTURES_MODE_ARMED;
    }
    *(u8 *)(obj + 0x36) = WCAPERTURES_INITIAL_ALPHA;
    WCAPERTURES_TARGET_ALPHA(state) = WCAPERTURES_ALPHA_OPAQUE;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), postRenderSetAlphaBlendState);
    WCAPERTURES_LIGHT(state) = objCreateLight(obj, 1);
    if (WCAPERTURES_LIGHT(state) != NULL) {
        modelLightStruct_setLightKind(WCAPERTURES_LIGHT(state), WCAPERTURES_LIGHT_KIND);
        if ((s8)*(u8 *)(obj + 0xad) == 0)
            modelLightStruct_setupGlow(WCAPERTURES_LIGHT(state), 0, 0xff, 0xff, WCAPERTURES_LIGHT_BLUE_LO,
                                       WCAPERTURES_LIGHT_BLUE_HI, lbl_803E6E3C);
        else
            modelLightStruct_setupGlow(WCAPERTURES_LIGHT(state), 0, WCAPERTURES_LIGHT_BLUE_LO,
                                       WCAPERTURES_LIGHT_BLUE_LO, 0xff, 0xff, lbl_803E6E3C);
        modelLightStruct_setGlowProjectionRadius(WCAPERTURES_LIGHT(state), lbl_803E6E40);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcapertures_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    int player = Obj_GetPlayerObject();
    void *light;
    int alpha, target;

    WCAPERTURES_TARGET_ALPHA(state) = 0;
    switch (WCAPERTURES_MODE(state)) {
    case WCAPERTURES_MODE_CLOSED:
        if ((u32)GameBit_Get(*(s16 *)(setup + WCAPERTURES_SETUP_ARM_BIT_OFFSET)) != 0) {
            WCAPERTURES_MODE(state) = WCAPERTURES_MODE_ARMED;
        }
        break;
    case WCAPERTURES_MODE_ARMED:
        if ((*(int (**)(void))(*gCameraInterface + 0x10))() == WCAPERTURES_CAMERA_MODE &&
            fn_802969F0(player) == WCAPERTURES_PLAYER_STATE) {
            WCAPERTURES_TARGET_ALPHA(state) = WCAPERTURES_ALPHA_OPAQUE;
            if (Camera_GetFovY() <= lbl_803E6E38 && (*(u16 *)(obj + 0xb0) & WCAPERTURES_ACCEPT_OBJECT_FLAG)) {
                GameBit_Set(*(s16 *)(setup + WCAPERTURES_SETUP_OPEN_BIT_OFFSET), 1);
                WCAPERTURES_MODE(state) = WCAPERTURES_MODE_OPEN;
            }
        }
        break;
    case WCAPERTURES_MODE_OPEN:
        WCAPERTURES_TARGET_ALPHA(state) = 0;
        break;
    }
    alpha = *(u8 *)(obj + 0x36);
    target = WCAPERTURES_TARGET_ALPHA(state);
    if (alpha < target) {
        int v = alpha + (framesThisStep << WCAPERTURES_ALPHA_STEP_SHIFT);
        if (v > target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    } else if (alpha > target) {
        int v = alpha - (framesThisStep << WCAPERTURES_ALPHA_STEP_SHIFT);
        if (v < target) {
            v = target;
        }
        *(u8 *)(obj + 0x36) = v;
    }
    light = WCAPERTURES_LIGHT(state);
    if (light != NULL) {
        if (*(u8 *)(obj + 0x36) > WCAPERTURES_LIGHT_ENABLE_THRESHOLD) {
            modelLightStruct_setEnabled(light, 1, lbl_803E6E2C);
        } else {
            modelLightStruct_setEnabled(light, 0, lbl_803E6E2C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
