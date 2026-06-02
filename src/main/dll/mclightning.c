#include "main/dll/dll_80220608_shared.h"

#pragma peephole off
#pragma scheduling off
int mclightning_handleScriptEvents(int obj, int eventId, u8 *script) {
    int state = *(int *)(obj + 0xb8);
    int i;
    for (i = 0; i < script[0x8b]; i++) {
        McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
        switch (f->hi) {
        case 0:
            f->hi = 1;
            *(f32 *)(state + 8) = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 1:
            f->hi = 2;
            *(f32 *)(state + 0xc) = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 2:
            f->hi = 3;
            *(u8 *)(state + 0x18) = script[0x81 + i];
            break;
        case 3:
            f->hi = 4;
            *(u8 *)(state + 0x19) = script[0x81 + i];
            break;
        case 4:
            f->hi = 5;
            *(u8 *)(state + 0x1a) = script[0x81 + i];
            *(s16 *)(obj + 6) &= ~0x4000;
            break;
        default:
            f->hi = 0xa;
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int mclightning_getExtraSize(void) { return 0x1c; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_free(int obj)
{
    int state = *(int *)(obj + 0xb8);

    ObjGroup_RemoveObject(obj, 0x48);
    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
        *(int *)state = 0;
    }
    ((McLightningFlags *)(state + 0x1b))->hi = 0;
    *(s16 *)(obj + 6) |= 0x4000;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);
    f32 v;

    *(s16 *)(obj + 6) |= 0x4000;
    *(void **)(obj + 0xbc) = (void *)mclightning_handleScriptEvents;
    ObjGroup_AddObject(obj, 0x48);
    ((McLightningFlags *)(state + 0x1b))->lo = setup[0x1a];
    v = lbl_803E745C;
    *(f32 *)(state + 0x10) = v;
    *(f32 *)(state + 0x14) = v;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale) {
    int state = *(int *)(obj + 0xb8);
    McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
    u32 mode = f->hi;
    if (mode == 5) {
        int count;
        int *objs = ObjGroup_GetObjects(0x48, &count);
        int i;
        for (i = 0; i < count; i++) {
            int *o = (int *)objs[i];
            if (*(u8 *)(*(int *)((int)o + 0x4c) + 0x1b) == *(u8 *)(state + 0x1a))
                break;
        }
        if (i == count) {
            f->hi = 0xa;
        } else {
            int foundState;
            McLightningFlags *ff;
            *(void **)(state + 0) =
                fn_8008FB20((f32 *)(obj + 0xc), (f32 *)(objs[i] + 0xc), *(f32 *)(state + 8),
                            *(f32 *)(state + 0xc), *(u8 *)(state + 0x18), *(u8 *)(state + 0x19), 0);
            f->hi = 6;
            *(f32 *)(state + 4) = lbl_803E7450;
            if (f->lo & 1) {
                hitDetectFn_80097070(obj, 1, 7, *(f32 *)(state + 0x10), 0x1e, 0);
            }
            foundState = *(int *)(objs[i] + 0xb8);
            ff = (McLightningFlags *)(foundState + 0x1b);
            if (ff->lo & 1) {
                hitDetectFn_80097070(objs[i], 1, 7, *(f32 *)(foundState + 0x10), 0x1e, 0);
            }
            if (f->lo & 2) {
                objFn_800972dc(obj, 5, 1, 1, *(f32 *)(state + 0x14), lbl_803E7454, 0x64, 0, 0);
            }
            if (ff->lo & 2) {
                objFn_800972dc(objs[i], 5, 1, 1, *(f32 *)(foundState + 0x14), lbl_803E7454, 0x64, 0,
                               0);
            }
        }
    } else if (mode == 6) {
        if (*(void **)(state + 0) != NULL) {
            u32 frame;
            renderFn_8008f904(*(void **)(state + 0));
            *(f32 *)(state + 4) += timeDelta;
            frame = (u16)(lbl_803E7458 + *(f32 *)(state + 4));
            *(u16 *)((int)*(void **)(state + 0) + 0x20) = frame;
            if (*(u16 *)((int)*(void **)(state + 0) + 0x20) >=
                *(u16 *)((int)*(void **)(state + 0) + 0x22)) {
                mm_free(*(void **)(state + 0));
                *(void **)(state + 0) = NULL;
                f->hi = 0;
                *(s16 *)(obj + 6) |= 0x4000;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
