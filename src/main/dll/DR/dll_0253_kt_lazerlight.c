#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"

typedef struct KtlazerlightPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} KtlazerlightPlacement;


int ktlazerlight_getExtraSize(void) { return 0x14; }

int ktlazerlight_getObjectTypeId(void) { return 0x0; }

void ktlazerlight_hitDetect(void) {}

void ktlazerlight_initialise(void) {}

void ktlazerlight_release(void) {}

void ktlazerlight_render(void) {}

void ktlazerlight_free(int obj) {
    void *p = ((GameObject *)obj)->extra;
    void *m = *(void **)((char *)p + 0x4);
    if (m != 0) {
        ModelLightStruct_free(m);
    }
}

void ktlazerlight_init(int obj, char *arg) {
    char *p = ((GameObject *)obj)->extra;
    *(void **)(p + 0x4) = objCreateLight(0, 1);
    if (*(void **)(p + 0x4) != 0) {
        modelLightStruct_setLightKind(*(void **)(p + 0x4), 2);
        modelLightStruct_setPosition(*(void **)(p + 0x4), *(f32 *)(arg + 0x8), *(f32 *)(arg + 0xc), *(f32 *)(arg + 0x10));
        modelLightStruct_setAffectsAabbLightSelection(*(void **)(p + 0x4), 1);
    }
}

void ktlazerlight_update(int obj) {
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    char *p = ((GameObject *)obj)->extra;
    s16 v;
    void *light = *(void **)(p + 0x4);
    v = (s16)GameBit_Get(((KtlazerlightPlacement *)q)->unk1A);
    if (v >= 1 || GameBit_Get(((KtlazerlightPlacement *)q)->unk1C) != 0) {
        if (v == 0) {
            v = 0x10;
        }
        if (light != 0) {
            modelLightStruct_setEnabled(light, 1, lbl_803E68C0);
            modelLightStruct_setDiffuseColor(light, 0x64, 0x6e, 0xff, 0xff);
            modelLightStruct_setDistanceAttenuation(*(void **)(p + 0x4), (f32)(v * 0x1a), (f32)(v * 0x1a + 0x14));
        }
    } else {
        if (light != 0) {
            modelLightStruct_setEnabled(light, 0, lbl_803E68C0);
        }
    }
}
