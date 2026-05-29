#include "main/dll/VF/vf_shared.h"

int vfplevelcontrol_getExtraSize(void) { return 0x1c; }

int vfplevelcontrol_getObjectTypeId(void) { return 0x0; }

void vfplevelcontrol_render(void) {}

void vfplevelcontrol_hitDetect(void) {}

void vfplevelcontrol_release(void) {}

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_initialise(void) {
    lbl_803DC148 = 0x82;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_free(int obj) {
    timeOfDayFn_80055000();
    ObjGroup_RemoveObject(obj, 9);
    Music_Trigger(0xe1, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void vfplevelcontrol_init(int *obj, u8 *init) {
    int *inner = *(int **)((char *)obj + 0xb8);
    ObjGroup_AddObject(obj, 9);
    *(s16 *)((char *)inner + 2) = 0;
    *(s16 *)((char *)inner + 4) = 0;
    *(s16 *)((char *)inner + 6) = 0;
    *(s16 *)((char *)inner + 8) = 0;
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = 0;
    *(s16 *)((char *)inner + 0xe) = 1;
    if (*(s16 *)((char *)init + 0x1a) != 0 && *(s16 *)((char *)init + 0x1a) <= 2) {
        *(s16 *)((char *)inner + 0xe) = *(s16 *)((char *)init + 0x1a);
    }
    lbl_803DC148 = 0x82;
    (*(void (*)(int))(*(int *)(*gMapEventInterface + 0x40)))((s8)*(u8 *)((char *)obj + 0xac));
    *(s16 *)((char *)inner + 0xa) = 0;
    *(s16 *)((char *)inner + 0xc) = 0;
    *(u16 *)((char *)obj + 0xb0) |= 0x6000;
    timeOfDayFn_80055038();
    GameBit_Set(0xdcf, 1);
    unlockLevel(0, 0, 1);
    if ((u32)GameBit_Get(0xe1b) != 0) {
        *(u8 *)((char *)inner + 0x18) = 4;
    } else {
        GameBit_Set(0xe1a, 0);
        GameBit_Set(0xe19, 0);
        GameBit_Set(0xe17, 0);
        GameBit_Set(0xe18, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_801F9804(int obj) {
    int inner = *(int *)((char *)obj + 0xb8);
    s16 bits[4];
    s16 *p;
    int i;

    if (*(u8 *)(inner + 0x18) < 4) {
        bits[0] = GameBit_Get(0xe1a);
        bits[1] = GameBit_Get(0xe19);
        bits[2] = GameBit_Get(0xe17);
        bits[3] = GameBit_Get(0xe18);
        p = &bits[*(u8 *)(inner + 0x18)];
        for (i = *(u8 *)(inner + 0x18); i < 4; i++) {
            if (i == *(u8 *)(inner + 0x18)) {
                if (*p != 0) {
                    *(u8 *)(inner + 0x18) = *(u8 *)(inner + 0x18) + 1;
                    if (*(u8 *)(inner + 0x18) == 4) {
                        GameBit_Set(0xe1b, 1);
                    }
                }
            } else if (*p != 0) {
                *(u8 *)(inner + 0x18) = 0;
                GameBit_Set(0xe1a, 0);
                GameBit_Set(0xe19, 0);
                GameBit_Set(0xe17, 0);
                GameBit_Set(0xe18, 0);
                break;
            }
            p++;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
