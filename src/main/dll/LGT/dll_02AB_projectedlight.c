#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int projectedlight_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int projectedlight_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void projectedlight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)state != NULL) {
        ModelLightStruct_free(*(void **)state);
    }
    if (*(void **)(state + 4) != NULL) {
        textureFree(*(void **)(state + 4));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void projectedlight_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void projectedlight_render(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void projectedlight_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x20) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x22) * timeDelta + (f32)*(s16 *)(obj + 2));
    *(s16 *)(obj + 4) =
        (s16)((f32)(*(s8 *)(setup + 0x35) << 4) * timeDelta + (f32)*(s16 *)(obj + 4));
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void projectedlight_init(int obj, int setup)
{
    PointLightVec vec;
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C2618;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);
    *(s16 *)(obj + 4) = (s16)(*(u8 *)(setup + 0x34) << 8);

    if (*(void **)state == NULL) {
        *(void **)state = objCreateLight(obj, 1);
    }

    if (*(void **)state != NULL) {
        modelLightStruct_setField50(*(void **)state, 8);
        lightVecFn_8001dd88(*(void **)state, lbl_803E7270, lbl_803E7270, lbl_803E7270);
        modelStruct2_setVectors(*(void **)state, vec.x, vec.y, vec.z);
        modelLightStruct_setColorsA8AC(*(void **)state, *(u8 *)(setup + 0x2d),
            *(u8 *)(setup + 0x2e), *(u8 *)(setup + 0x2f), *(u8 *)(setup + 0x37));
        lightDistAttenFn_8001dc38(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x1a),
            (f32)(u32)*(u16 *)(setup + 0x1c));
        fn_8001DB24(*(void **)state, *(u8 *)(setup + 0x39));
        modelLightStruct_setEnabled(*(void **)state, *(u8 *)(setup + 0x3a), lbl_803E7270);

        if (*(void **)(state + 4) == NULL) {
            if (*(u16 *)(setup + 0x24) != 0) {
                *(void **)(state + 4) = textureLoadAsset(*(u16 *)(setup + 0x24));
            } else {
                *(void **)(state + 4) = textureLoadAsset(0x5dc);
            }
            fn_8001D98C(*(void **)state, *(void **)(state + 4));
        }

        if (*(u8 *)(setup + 0x26) == 0) {
            f32 a = (f32)(u32)*(u16 *)(setup + 0x28) / lbl_803E7274;
            f32 b;
            f32 lo, hi;
            if (a < lbl_803E7260) {
                a = lbl_803E7260;
            }
            b = (f32)(u32)*(u16 *)(setup + 0x2a) / lbl_803E7274;
            if (b < lbl_803E7260) {
                b = lbl_803E7260;
            }
            if (*(u8 *)(setup + 0x3f) != 0) {
                u8 v = *(u8 *)(setup + 0x3f);
                lo = (f32)(v & 0xf);
                hi = (f32)((v >> 4) & 0xf);
            } else {
                lo = lbl_803E7260;
                hi = lo;
            }
            fn_8001D8F0(*(void **)state, b, -b, -a, a, lo, hi);
        } else {
            f32 c = (f32)(u32)*(u16 *)(setup + 0x28) / lbl_803E7274;
            f32 d;
            if (c < lbl_803E7260) {
                c = lbl_803E7260;
            }
            d = (f32)(u32)*(u16 *)(setup + 0x2a) / lbl_803E7274;
            if (d < lbl_803E7260) {
                d = lbl_803E7260;
            }
            fn_8001D878(*(void **)state, (f32)(u32)*(u8 *)(setup + 0x27), c / d);
        }

        fn_8001D80C(*(void **)state, *(u8 *)(setup + 0x36), *(u8 *)(setup + 0x3e));
        fn_8001D84C(*(void **)state, (f32)(u32)*(u8 *)(setup + 0x3b));
        fn_8001D820(*(void **)state, (f32)(u32)*(u16 *)(setup + 0x3c));
        modelLightStruct_startColorFade(*(void **)state, *(u8 *)(setup + 0x33), *(s16 *)(setup + 0x1e));
        lightSetFieldB0(*(void **)state, *(u8 *)(setup + 0x30), *(u8 *)(setup + 0x31),
            *(u8 *)(setup + 0x32), *(u8 *)(setup + 0x38));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void projectedlight_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void projectedlight_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
