#include "main/dll/torch1CD.h"
#include "main/dll/torch1cd_state.h"

extern void getEnvfxAct(int obj, int target, int id, int p);
extern void GameBit_Set(int eventId, int value);
extern void *return0_8005669C(int);
extern int *gTitleMenuControlInterface;

extern int lbl_803DB610;
extern void *lbl_803DDBE0;

/*
 * --INFO--
 *
 * Function: dll_19B_SeqFn
 * EN v1.0 Address: 0x801CBA98
 * EN v1.0 Size: 636b
 */
#pragma peephole off
#pragma scheduling off
int dll_19B_SeqFn(int obj, int unused, u8 *buf)
{
    int state;
    int i;

    state = *(int *)(obj + 0xb8);
    *(s16 *)(buf + 0x6e) = -1;
    buf[0x56] = 0;

    if (((Torch1CDState *)state)->unkA != 0) {
        ((Torch1CDState *)state)->unk8 += ((Torch1CDState *)state)->unkA;
        if (((Torch1CDState *)state)->unk8 <= 1 && ((Torch1CDState *)state)->unkA <= 0) {
            ((Torch1CDState *)state)->unk8 = 1;
            ((Torch1CDState *)state)->unkA = 0;
        } else if (((Torch1CDState *)state)->unk8 >= 0x46 && ((Torch1CDState *)state)->unkA >= 0) {
            ((Torch1CDState *)state)->unk8 = 0x46;
            ((Torch1CDState *)state)->unkA = 0;
        }
        ((void (**)(int, u8))*gTitleMenuControlInterface)[0x38/4](3, (u8)((Torch1CDState *)state)->unk8);
    }

    for (i = 0; i < (int)buf[0x8b]; i++) {
        u8 cmd = buf[0x81 + i];
        if (cmd != 0) {
            switch (cmd) {
            case 1:
                getEnvfxAct(obj, obj, 0xc3, 0);
                break;
            case 2:
                if (lbl_803DB610 == -1) {
                    getEnvfxAct(obj, obj, 0x14, 0);
                } else {
                    getEnvfxAct(obj, obj, lbl_803DB610 & 0xffff, 0);
                }
                break;
            case 3:
                ((Torch1CDState *)state)->unk14 = 1;
                break;
            case 4:
                ((Torch1CDState *)state)->unk13 = 4;
                ((Torch1CDState *)state)->unk14 = 2;
                GameBit_Set(0x129, 1);
                GameBit_Set(0x1d2, 0);
                GameBit_Set(0x126, 1);
                ((Torch1CDState *)state)->unkA = -3;
                break;
            case 5:
                ((Torch1CDState *)state)->unk13 = 6;
                ((Torch1CDState *)state)->unk14 = 3;
                ((Torch1CDState *)state)->unkA = -3;
                GameBit_Set(0x129, 1);
                break;
            case 6:
                GameBit_Set(0x1d2, 1);
                break;
            case 7:
                GameBit_Set(0x1d2, 0);
                ((Torch1CDState *)state)->unkA = -3;
                break;
            case 8:
                GameBit_Set(0x128, 1);
                if (lbl_803DDBE0 == NULL) {
                    lbl_803DDBE0 = return0_8005669C(1);
                }
                break;
            case 9:
                GameBit_Set(0x127, 1);
                break;
            case 0xb:
                ((Torch1CDState *)state)->unk8 = 100;
                ((void (**)(int, int, int, u8, int))*gTitleMenuControlInterface)[0x18/4]
                    (3, 0x2d, 0x50, (u8)((Torch1CDState *)state)->unk8, 0);
                break;
            }
        }
        buf[0x81 + i] = 0;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/* Trivial 4b 0-arg blr leaves. */
void dll_19B_hitDetect(void) {}

/* 8b "li r3, N; blr" returners. */
int dll_19B_getExtraSize(void) { return 0x18; }
int dll_19B_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E5188;
extern void objRenderFn_8003b8f4(f32);
#pragma peephole off
void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E5188); }
#pragma peephole reset

extern undefined4 *gModgfxInterface;
#pragma scheduling off
#pragma peephole off
void dll_19B_free(int *obj) {
    ((void (*)(int *))((void **)*gModgfxInterface)[6])(obj);
}
#pragma peephole reset
#pragma scheduling reset
