#include "main/dll/DR/dr_shared.h"
#include "main/mapEventTypes.h"

int gmmazewell_getExtraSize(void) { return 0x8; }

#pragma scheduling off
#pragma peephole off
void gmmazewell_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6978);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gmmazewell_free(void) {
    GameBit_Set(0xefc, 0);
    Music_Trigger(0x36, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gmmazewell_init(int obj) {
    u8 *p = *(u8 **)((char *)obj + 0xb8);
    p[0] = 0;
    GameBit_Set(0xefc, 1);
    Music_Trigger(0x36, 1);
    *(void **)((char *)obj + 0xbc) = (void *)gmmazewell_clearPendingTriggerCallback;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
int gmmazewell_clearPendingTriggerCallback(int obj, int unused, u8 *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int i;
    for (i = 0; i < arg[0x8b]; i++) {
        if (arg[i + 0x81] == 1 && *(int *)(p + 0x4) != -1) {
            (*(void (**)(int, int, int, int))((char *)*gGameUIInterface + 0x38))(*(int *)(p + 0x4), 0x14, 0x8c, 0);
            *(int *)(p + 0x4) = -1;
        }
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void gmmazewell_update(void *obj) {
    s16 *base = lbl_8032A730;
    u8 *runtime = *(u8 **)((char *)obj + 0xb8);
    int player;
    int value;
    s16 *p;
    int i;
    if (runtime[1] == 0) {
        player = (int)Obj_GetPlayerObject();
        if (player != 0) {
            ((MapEventInterface *)*gMapEventInterface)->triggerEvent(
                player + 0xc, *(s16 *)player, 0, getCurMapLayer());
            runtime[1] = 1;
        }
    }
    *(u8 *)((char *)obj + 0xaf) &= ~8;
    p = base;
    for (i = 0; i < 9; i++) {
        if (GameBit_Get(*p) != 0) {
            value = base[i];
            goto checkValue;
        }
        p++;
    }
    value = 0;
checkValue:
    if (value != 0) {
        *(u8 *)((char *)obj + 0xaf) &= ~0x10;
    } else {
        *(u8 *)((char *)obj + 0xaf) |= 0x10;
    }
    if ((*(u8 *)((char *)obj + 0xaf) & 1) != 0) {
        int found;
        p = base;
        for (i = 0; i < 9; i++) {
            if ((*(int (**)(int))((char *)*gGameUIInterface + 0x20))(*p) != 0) {
                if (lbl_803DC968 != 0) {
                    runtime = *(u8 **)((char *)obj + 0xb8);
                    if (i < 3 && i >= 0) {
                        GameBit_Set(*(s16 *)((char *)&base[i] + 0x14), 1);
                        saveFileStruct_unlockCheat((u8)i);
                    }
                    *(int *)(runtime + 4) = *(s32 *)((char *)&base[i * 2] + 0x38);
                    GameBit_Set(*(s16 *)((char *)&base[i] + 0x28), 1);
                } else {
                    runtime = *(u8 **)((char *)obj + 0xb8);
                    *(int *)(runtime + 4) = *(s32 *)((char *)&base[i * 2] + 0x38);
                    if (i == 3) {
                        *(int *)(runtime + 4) = 1316;
                    }
                    if (i < 3 && i >= 0) {
                        GameBit_Set(*(s16 *)((char *)&base[i] + 0x14), 1);
                        saveFileStruct_unlockCheat((u8)i);
                    }
                    GameBit_Set(*(s16 *)((char *)&base[i] + 0x28), 1);
                }
                found = 1;
                goto checkFound;
            }
            p++;
        }
        found = 0;
    checkFound:
        if (found != 0) {
            (*(void (**)(int, void *, int))((char *)*gObjectTriggerInterface + 0x48))(0, obj, -1);
            buttonDisable(0, 256);
        }
    }
    objRenderFn_80041018((int)obj);
}
#pragma peephole reset
#pragma scheduling reset
