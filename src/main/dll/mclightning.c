#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/dll/mclightning_state.h"

#pragma peephole off
#pragma scheduling off
int mclightning_handleScriptEvents(int obj, int eventId, u8 *script) {
    int state = *(int *)&((GameObject *)obj)->extra;
    int i;
    for (i = 0; i < script[0x8b]; i++) {
        McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
        switch (f->hi) {
        case 0:
            f->hi = 1;
            ((McLightningState *)state)->unk8 = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 1:
            f->hi = 2;
            ((McLightningState *)state)->unkC = lbl_803E7440 * (f32)(u32)script[0x81 + i];
            break;
        case 2:
            f->hi = 3;
            ((McLightningState *)state)->unk18 = script[0x81 + i];
            break;
        case 3:
            f->hi = 4;
            ((McLightningState *)state)->unk19 = script[0x81 + i];
            break;
        case 4:
            f->hi = 5;
            ((McLightningState *)state)->unk1A = script[0x81 + i];
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
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

int mclightning_getExtraSize(void) { return 0x1c; }

#pragma scheduling off
void mclightning_free(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    ObjGroup_RemoveObject(obj, 0x48);
    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
    }
}
#pragma scheduling reset

#pragma peephole off
#pragma scheduling off
void mclightning_update(int obj)
{
    int state = *(int *)&((GameObject *)obj)->extra;

    if (*(void **)state != NULL) {
        mm_free(*(void **)state);
        *(int *)state = 0;
    }
    ((McLightningFlags *)(state + 0x1b))->hi = 0;
    ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_init(int obj, u8 *setup)
{
    int state = *(int *)&((GameObject *)obj)->extra;
    f32 v;

    ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    ((GameObject *)obj)->animEventCallback = (void *)mclightning_handleScriptEvents;
    ObjGroup_AddObject(obj, 0x48);
    ((McLightningFlags *)(state + 0x1b))->lo = setup[0x1a];
    v = lbl_803E745C;
    ((McLightningState *)state)->unk10 = v;
    ((McLightningState *)state)->unk14 = v;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void mclightning_render(int obj, int p2, int p3, int p4, int p5, f32 scale) {
    int state = *(int *)&((GameObject *)obj)->extra;
    McLightningFlags *f = (McLightningFlags *)(state + 0x1b);
    u32 mode = f->hi;
    if (mode == 5) {
        int count;
        int *objs = ObjGroup_GetObjects(0x48, &count);
        int i;
        for (i = 0; i < count; i++) {
            int *o = (int *)objs[i];
            if (*(u8 *)(*(int *)((int)o + 0x4c) + 0x1b) == ((McLightningState *)state)->unk1A)
                break;
        }
        if (i == count) {
            f->hi = 0xa;
        } else {
            int foundState;
            McLightningFlags *ff;
            ((McLightningState *)state)->unk0 =
                lightningCreate(&((GameObject *)obj)->anim.localPosX, (f32 *)(objs[i] + 0xc), ((McLightningState *)state)->unk8,
                            ((McLightningState *)state)->unkC, ((McLightningState *)state)->unk18, ((McLightningState *)state)->unk19, 0);
            f->hi = 6;
            ((McLightningState *)state)->unk4 = lbl_803E7450;
            if (f->lo & 1) {
                hitDetectFn_80097070(obj, 1, 7, ((McLightningState *)state)->unk10, 0x1e, 0);
            }
            foundState = *(int *)(objs[i] + 0xb8);
            ff = (McLightningFlags *)(foundState + 0x1b);
            if (ff->lo & 1) {
                hitDetectFn_80097070(objs[i], 1, 7, *(f32 *)(foundState + 0x10), 0x1e, 0);
            }
            if (f->lo & 2) {
                objfx_spawnDirectionalBurst(obj, 5, 1, 1, ((McLightningState *)state)->unk14, lbl_803E7454, 0x64, 0, 0);
            }
            if (ff->lo & 2) {
                objfx_spawnDirectionalBurst(objs[i], 5, 1, 1, *(f32 *)(foundState + 0x14), lbl_803E7454, 0x64, 0,
                               0);
            }
        }
    } else if (mode == 6) {
        if (((McLightningState *)state)->unk0 != NULL) {
            u32 frame;
            lightningRender(((McLightningState *)state)->unk0);
            ((McLightningState *)state)->unk4 += timeDelta;
            frame = (u16)(lbl_803E7458 + ((McLightningState *)state)->unk4);
            *(u16 *)((int)((McLightningState *)state)->unk0 + 0x20) = frame;
            if (*(u16 *)((int)((McLightningState *)state)->unk0 + 0x20) >=
                *(u16 *)((int)((McLightningState *)state)->unk0 + 0x22)) {
                mm_free(((McLightningState *)state)->unk0);
                ((McLightningState *)state)->unk0 = NULL;
                f->hi = 0;
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
