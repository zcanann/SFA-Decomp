#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on

typedef struct PointLightState {
    void *light;
    u8 enabled;
} PointLightState;

int pointlight_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int pointlight_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_setEffectState(int obj, int flag)
{
    PointLightState *state = *(PointLightState **)(obj + 0xb8);
    void *light = state->light;
    if (light != NULL) {
        modelLightStruct_setEnabled(light, flag, lbl_803E7230);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void pointlight_free(int obj)
{
    PointLightState *state = *(PointLightState **)(obj + 0xb8);
    if (state->light != NULL) {
        ModelLightStruct_free(state->light);
    }
    ObjGroup_RemoveObject(obj, 0x35);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_render(int obj)
{
    PointLightState *state = *(PointLightState **)(obj + 0xb8);
    void *light = state->light;
    if (light != NULL && *(u8 *)((char *)light + 0x2f8) != 0 &&
        *(u8 *)((char *)light + 0x4c) != 0) {
        queueGlowRender(light);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void pointlight_update(int obj)
{
    u8 colorR, colorG, colorB;
    int setup = *(int *)(obj + 0x4c);
    PointLightState *state = *(PointLightState **)(obj + 0xb8);

    if (state->light == NULL) {
        return;
    }

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x32) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x34) * timeDelta + (f32)*(s16 *)(obj + 2));

    if (state->enabled != 0) {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) == 0) {
            state->enabled = 0;
            modelLightStruct_setEnabled(state->light, 0, lbl_803E7234);
        }
        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        }
    } else {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) != 0) {
            state->enabled = 1;
            modelLightStruct_setEnabled(state->light, 1, lbl_803E7234);
        }
    }

    if (state->light != NULL) {
        modelLightStruct_updateGlowAlpha(state->light);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void pointlight_init(int obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    PointLightState *state = *(PointLightState **)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C25F8;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);

    if (state->light == NULL) {
        state->light = objCreateLight(obj, 1);
    }

    if (state->light != NULL) {
        modelLightStruct_setLightKind(state->light, 2);
        objSetEventName(state->light, *(u8 *)(setup + 0x1d));
        modelLightStruct_setPosition(state->light, lbl_803E7230, lbl_803E7230, lbl_803E7230);

        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setDiffuseColor(state->light, colorR, colorG, colorB, 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, colorR, colorG, colorB, 0xff);
        } else {
            modelLightStruct_setDiffuseColor(state->light, *(u8 *)(setup + 0x1a),
                *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), 0xff);
            modelLightStruct_setDiffuseTargetColor(state->light, *(u8 *)(setup + 0x27),
                *(u8 *)(setup + 0x28), *(u8 *)(setup + 0x29), 0xff);
        }

        modelLightStruct_setDistanceAttenuation(state->light, (f32)(u32)*(u16 *)(setup + 0x22),
            (f32)(u32)*(u16 *)(setup + 0x24));

        {
            u8 brightness = *(u8 *)(setup + 0x20);
            if (brightness >= 0x5a) {
                brightness = 0x5a;
            }
            modelLightStruct_setSpotAttenuation(state->light, (f32)brightness, *(u8 *)(setup + 0x21));
        }

        modelLightStruct_setEnabled(state->light, *(u8 *)(setup + 0x30), lbl_803E7230);
        state->enabled = *(u8 *)(setup + 0x30);
        modelLightStruct_startColorFade(state->light, *(u8 *)(setup + 0x26), *(s16 *)(setup + 0x2e));
        modelLightStruct_setDirection(state->light, vec.x, vec.y, vec.z);

        if (*(u8 *)(setup + 0x21) != 0) {
            Obj_SetActiveModelIndex(obj, 1);
        } else {
            Obj_SetActiveModelIndex(obj, 0);
        }

        if (*(u8 *)(setup + 0x3e) != 0) {
            modelLightStruct_setupGlow(state->light, *(u16 *)(setup + 0x38), *(u8 *)(setup + 0x3a),
                *(u8 *)(setup + 0x3b), *(u8 *)(setup + 0x3c), *(u8 *)(setup + 0x3d),
                (f32)(u32)*(u16 *)(setup + 0x36));
            modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E7240);
        }

        if (*(u8 *)(setup + 0x3f) != 0) {
            modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        }

        if (*(u8 *)(setup + 0x2c) != 0) {
            modelLightStruct_setSelectionPriority(state->light, *(u8 *)(setup + 0x2c));
        }
    }

    ObjGroup_AddObject(obj, 0x35);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
