#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling off
int wctrexstatu_interactCallback(int obj, int unused, int callbackData)
{
    int i;

    for (i = 0; i < *(u8 *)(callbackData + 0x8b); i++) {
        if (*(u8 *)(callbackData + 0x81 + i) == 1) {
            int *texture = objFindTexture(obj, 0, 0);

            if (texture != NULL) {
                *texture = 0x100;
            }
            *(int *)(obj + 0xf4) = 1;
        }
    }

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wctrexstatu_getExtraSize(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wctrexstatu_getObjectTypeId(int obj)
{
    int modelIndex = *(s8 *)(*(int *)(obj + 0x4c) + 0x19);
    int modelCount = *(s8 *)(*(int *)(obj + 0x50) + 0x55);

    if (modelIndex >= modelCount) {
        modelIndex = 0;
    }
    return (modelIndex << 0xb) | 0x400;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wctrexstatu_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E10);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wctrexstatu_hitDetect(u8 *obj)
{
    if (*(int *)(obj + 0xf4) != 0 && randomGetRange(0, 5) == 0) {
        if (*(s8 *)(obj + 0xad) == 0) {
            (*(void (**)(u8 *, int, int, int, int, u8 *))(*gPartfxInterface + 8))(obj, 0x73f, 0, 2, -1, obj);
        } else {
            (*(void (**)(u8 *, int, int, int, int, u8 *))(*gPartfxInterface + 8))(obj, 0x740, 0, 2, -1, obj);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_update(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wctrexstatu_init(int obj, int setup, int fromLoad)
{
    *(void **)(obj + 0xbc) = wctrexstatu_interactCallback;
    *(u8 *)(obj + 0xad) = *(u8 *)(setup + 0x19);
    if ((s8)*(u8 *)(obj + 0xad) >= (s8)*(u8 *)(*(int *)(obj + 0x50) + 0x55)) {
        *(u8 *)(obj + 0xad) = 0;
    }

    *(s16 *)obj = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    if (fromLoad == 0) {
        if ((u32)(*(int (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac)) == 2) {
            *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) + lbl_803E6E14;
        }
    }

    if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
        int *texture = objFindTexture(obj, 0, 0);

        if (texture != NULL) {
            *texture = 0x100;
        }
        *(int *)(obj + 0xf4) = 1;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wctrexstatu_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
