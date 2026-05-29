#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
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
    void *light = *(void **)*(int *)(obj + 0xb8);
    if (light != NULL) {
        lightFn_8001db6c(light, flag, lbl_803E7230);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void pointlight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    ObjGroup_RemoveObject(obj, 0x35);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void pointlight_render(int obj)
{
    void *light = *(void **)*(int *)(obj + 0xb8);
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
    int state = *(int *)(obj + 0xb8);

    if (*(void **)state == NULL) {
        return;
    }

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x32) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x34) * timeDelta + (f32)*(s16 *)(obj + 2));

    if (*(u8 *)(state + 4) != 0) {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) == 0) {
            *(u8 *)(state + 4) = 0;
            lightFn_8001db6c(*(void **)state, 0, lbl_803E7234);
        }
        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)state, colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)state, colorR, colorG, colorB, 0xff);
        }
    } else {
        s16 bit = *(s16 *)(setup + 0x1e);
        if (bit > 0 && (u32)GameBit_Get(bit) != 0) {
            *(u8 *)(state + 4) = 1;
            lightFn_8001db6c(*(void **)state, 1, lbl_803E7234);
        }
    }

    if (*(void **)state != NULL) {
        lightFn_8001d6b0(*(void **)state);
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
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C25F8;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);

    if (*(void **)state == NULL) {
        *(void **)state = objCreateLight(obj, 1);
    }

    if (*(void **)state != NULL) {
        modelLightStruct_setField50(*(void **)state, 2);
        objSetEventName(*(void **)state, *(u8 *)(setup + 0x1d));
        lightVecFn_8001dd88(*(void **)state, lbl_803E7230, lbl_803E7230, lbl_803E7230);

        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)state, colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)state, colorR, colorG, colorB, 0xff);
        } else {
            modelLightStruct_setColorsA8AC(*(void **)state, *(u8 *)(setup + 0x1a),
                *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), 0xff);
            lightSetFieldB0(*(void **)state, *(u8 *)(setup + 0x27),
                *(u8 *)(setup + 0x28), *(u8 *)(setup + 0x29), 0xff);
        }

        lightDistAttenFn_8001dc38(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x22),
            (f32)(u32)*(u16 *)(setup + 0x24));

        {
            u8 brightness = *(u8 *)(setup + 0x20);
            if (brightness >= 0x5a) {
                brightness = 0x5a;
            }
            fn_8001DA60(*(void **)state, (f32)brightness, *(u8 *)(setup + 0x21));
        }

        lightFn_8001db6c(*(void **)state, *(u8 *)(setup + 0x30), lbl_803E7230);
        *(u8 *)(state + 4) = *(u8 *)(setup + 0x30);
        lightFn_8001d620(*(void **)state, *(u8 *)(setup + 0x26), *(s16 *)(setup + 0x2e));
        modelStruct2_setVectors(*(void **)state, vec.x, vec.y, vec.z);

        if (*(u8 *)(setup + 0x21) != 0) {
            Obj_SetActiveModelIndex(obj, 1);
        } else {
            Obj_SetActiveModelIndex(obj, 0);
        }

        if (*(u8 *)(setup + 0x3e) != 0) {
            fn_8001D730(*(void **)state, *(u16 *)(setup + 0x38), *(u8 *)(setup + 0x3a),
                *(u8 *)(setup + 0x3b), *(u8 *)(setup + 0x3c), *(u8 *)(setup + 0x3d),
                (f32)(u32)*(u16 *)(setup + 0x36));
            fn_8001D714(*(void **)state, lbl_803E7240);
        }

        if (*(u8 *)(setup + 0x3f) != 0) {
            lightSetField2FB(*(void **)state, 1);
        }

        if (*(u8 *)(setup + 0x2c) != 0) {
            fn_8001DB5C(*(void **)state, *(u8 *)(setup + 0x2c));
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
