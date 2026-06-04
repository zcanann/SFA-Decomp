#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int arwproximit_getExtraSize(void) { return 0x18; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwproximit_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwproximit_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 4) != NULL) {
        ModelLightStruct_free(*(void **)(state + 4));
        *(void **)(state + 4) = NULL;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 4) != NULL && fn_8001DB64(*(void **)(state + 4)) != 0) {
        queueGlowRender(*(void **)(state + 4));
    }
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E71E4);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwproximit_init(int obj, int setup, int p3)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)(state + 0) = (s16)randomGetRange(0x64, 0x12c);
    *(u8 *)(state + 0x15) = *(u8 *)(setup + 0x31);
    if (p3 == 0) {
        *(s16 *)(obj + 2) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 4) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 0) = (s16)randomGetRange(0, 0xffff);
        *(s16 *)(obj + 6) |= 0x4000;
        *(u8 *)(obj + 0x36) = 0;
    }
    storeZeroToFloatParam((void *)(state + 0xc));
    storeZeroToFloatParam((void *)(state + 0x10));
    ObjHits_DisableObject(obj);
    ObjHits_MarkObjectPositionDirty(obj);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwproximit_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwproximit_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 0x15) == 1) {
        char *arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E71E8) {
            gameTextFn_80125ba4(0xb);
            *(u8 *)(state + 0x15) = 0;
        }
    }

    switch (*(u8 *)(state + 0x14)) {
    case 0: {
        char *arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E71EC) {
            *(void **)(state + 4) = objCreateLight(obj, 1);
            if (*(void **)(state + 4) != NULL) {
                modelLightStruct_setField50(*(void **)(state + 4), 2);
                lightVecFn_8001dd88(*(void **)(state + 4), lbl_803E71D8, lbl_803E71D8,
                                    lbl_803E71F0);
                modelLightStruct_setColorsA8AC(*(void **)(state + 4), 0, 0xff, 0, 0);
                lightSetFieldB0(*(void **)(state + 4), 0, 0, 0, 0);
                lightDistAttenFn_8001dc38(*(void **)(state + 4), lbl_803E71F0, lbl_803E71F4);
                fn_8001D730(*(void **)(state + 4), 0, 0, 0xff, 0, 0x64, lbl_803E71F8);
                fn_8001D714(*(void **)(state + 4), lbl_803E71F0);
            }
            ObjHits_EnableObject(obj);
            ObjHits_MarkObjectPositionDirty(obj);
            *(s16 *)(obj + 6) &= ~0x4000;
            *(u8 *)(state + 0x14) = 1;
        }
        return;
    }
    case 1:
    default: {
        char *arwing;
        int a = (int)(lbl_803E71FC * timeDelta + (f32)(u32)*(u8 *)(obj + 0x36));
        if (a > 0xff)
            a = 0xff;
        *(u8 *)(obj + 0x36) = a;
        arwing = (char *)getArwing();
        if (arwing == NULL)
            arwing = (char *)Obj_GetPlayerObject();
        if (Vec_distance(obj + 0x18, (int)(arwing + 0x18)) < lbl_803E7200) {
            if (*(void **)(state + 4) != NULL) {
                modelLightStruct_setColorsA8AC(*(void **)(state + 4), 0xff, 0, 0, 0);
                fn_8001D71C(*(void **)(state + 4), 0xff, 0, 0, 0x64);
                lightFn_8001d620(*(void **)(state + 4), 2, 0xa);
            }
            s16toFloat((void *)(state + 0xc), 0x3c);
            *(u8 *)(state + 0x14) = 2;
            if (*(u8 *)(state + 0x15) == 2) {
                if (randomGetRange(0, 1) != 0)
                    gameTextFn_80125ba4(0xf);
                else
                    gameTextFn_80125ba4(0xc);
            }
        }
        break;
    }
    case 2: {
        u8 b0, b1, b2, b3;
        *(u8 *)(obj + 0x36) = 0xff;
        if (*(void **)(state + 4) != NULL) {
            modelLightStruct_getColorsA8AC(*(void **)(state + 4), &b0, &b1, &b2, &b3);
            fn_8001D71C(*(void **)(state + 4), b0, b1, b2, 0x64);
        }
        if (timerCountDown((void *)(state + 0xc)) != 0 ||
            (*(void **)(*(int *)(obj + 0x54) + 0x50) != NULL &&
             *(void **)(*(int *)(obj + 0x54) + 0x50) == (void *)getArwing())) {
            storeZeroToFloatParam((void *)(state + 0xc));
            s16toFloat((void *)(state + 0x10), 0x14);
            if (*(void **)(state + 4) != NULL)
                lightFn_8001db6c(*(void **)(state + 4), 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71E0, 1, 0, 1, 1, 0, 0, 1);
            ObjHitbox_SetSphereRadius(obj, 0x12c);
            ObjHits_SetHitVolumeSlot(obj, 5, 1, 0);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_MarkObjectPositionDirty(obj);
            *(u8 *)(state + 0x14) = 3;
        }
        break;
    }
    case 3:
        if (timerCountDown((void *)(state + 0x10)) != 0) {
            ObjHits_DisableObject(obj);
            *(u8 *)(state + 0x14) = 4;
        }
        break;
    case 4:
        if (*(void **)(state + 4) != NULL) {
            ModelLightStruct_free(*(void **)(state + 4));
            *(void **)(state + 4) = NULL;
        }
        return;
    }

    if (*(u8 *)(state + 0x14) == 1 || *(u8 *)(state + 0x14) == 2) {
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            arwarwing_addScore(getArwing(), 0xa);
            if (*(u8 *)(state + 0x15) == 3)
                gameTextFn_80125ba4(0xe);
            if (*(void **)(state + 4) != NULL)
                lightFn_8001db6c(*(void **)(state + 4), 0, lbl_803E71D8);
            spawnExplosion(obj, lbl_803E71DC, 1, 0, 0, 0, 0, 0, 1);
            ObjHits_DisableObject(obj);
            *(s16 *)(obj + 6) |= 0x4000;
            ObjHits_MarkObjectPositionDirty(obj);
            *(u8 *)(state + 0x14) = 4;
        }
        *(s16 *)(obj + 4) =
            timeDelta * (f32)*(s16 *)(state + 0) + (f32)*(s16 *)(obj + 4);
        *(s16 *)(obj + 2) =
            timeDelta * (f32)*(s16 *)(state + 0) + (f32)*(s16 *)(obj + 2);
    }

    if (*(void **)(state + 4) != NULL && fn_8001DB64(*(void **)(state + 4)) != 0)
        lightFn_8001d6b0(*(void **)(state + 4));
}
#pragma scheduling reset
#pragma peephole reset
