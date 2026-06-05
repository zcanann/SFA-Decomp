#include "main/dll/DR/dr_shared.h"

int ktlazerlight_getExtraSize(void) { return 0x14; }

int ktlazerlight_getObjectTypeId(void) { return 0x0; }

void ktlazerlight_hitDetect(void) {}

void ktlazerlight_initialise(void) {}

void ktlazerlight_release(void) {}

void ktlazerlight_render(void) {}

#pragma scheduling off
#pragma peephole off
void ktlazerlight_free(int obj) {
    void *p = *(void **)((char *)obj + 0xb8);
    void *m = *(void **)((char *)p + 0x4);
    if (m != 0) {
        ModelLightStruct_free(m);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktlazerlight_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    *(void **)(p + 0x4) = objCreateLight(0, 1);
    if (*(void **)(p + 0x4) != 0) {
        modelLightStruct_setField50(*(void **)(p + 0x4), 2);
        lightVecFn_8001dd88(*(void **)(p + 0x4), *(f32 *)(arg + 0x8), *(f32 *)(arg + 0xc), *(f32 *)(arg + 0x10));
        lightSetField2FB(*(void **)(p + 0x4), 1);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktlazerlight_update(int obj) {
    int q = *(int *)((char *)obj + 0x4c);
    char *p = *(char **)((char *)obj + 0xb8);
    s16 v;
    void *light = *(void **)(p + 0x4);
    v = (s16)GameBit_Get(*(s16 *)(q + 0x1a));
    if (v >= 1 || GameBit_Get(*(s16 *)(q + 0x1c)) != 0) {
        if (v == 0) {
            v = 0x10;
        }
        if (light != 0) {
            modelLightStruct_setEnabled(light, 1, lbl_803E68C0);
            modelLightStruct_setColorsA8AC(light, 0x64, 0x6e, 0xff, 0xff);
            lightDistAttenFn_8001dc38(*(void **)(p + 0x4), (f32)(v * 0x1a), (f32)(v * 0x1a + 0x14));
        }
    } else {
        if (light != 0) {
            modelLightStruct_setEnabled(light, 0, lbl_803E68C0);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
