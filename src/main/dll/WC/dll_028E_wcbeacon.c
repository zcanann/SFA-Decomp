#include "main/dll/dll_80220608_shared.h"
#include "main/audio/sfx_ids.h"
#include "main/mapEventTypes.h"


#pragma peephole on
#pragma scheduling off
int wcbeacon_aButtonCallback(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (isGameTimerDisabled() == 0) {
        *(u8 *)(state + 5) = 1;
        GameBit_Set(*(s16 *)(setup + 0x1e), 1);
    }
    return 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcbeacon_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
int wcbeacon_getObjectTypeId(int obj)
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

#pragma peephole off
#pragma scheduling on
void wcbeacon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6DE0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbeacon_init(u8 *obj, u8 *setup)
{
    u8 *state = *(u8 **)(obj + 0xb8);
    s16 objType;

    ((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac));
    objType = (s16)((s8)setup[0x18] << 8);
    *(s16 *)obj = objType;
    obj[0xad] = setup[0x19];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            state[4] = 3;
        } else {
            state[4] = 1;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbeacon_update(int obj)
{
    int setup = *(int *)(obj + 0x4c);
    int state = *(int *)(obj + 0xb8);
    u32 phase;

    *(u8 *)(obj + 0xaf) |= 8;
    phase = *(u8 *)(state + 4);
    if (phase == 1) {
        int tricky = getTrickyObject();
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) == 0) {
            if ((u32)fn_80138F84(tricky) != (u32)obj || trickyFn_80138f14(tricky) != 0) {
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                *(u8 *)(state + 4) = 0;
            }
        } else {
            *(u8 *)(obj + 0xaf) &= ~8;
            if ((u32)tricky != 0 && (*(u8 *)(obj + 0xaf) & 4)) {
                (*(void (**)(int, int, int, int, int))(*(int *)(*(int *)(tricky + 0x68)) + 0x28))(
                    tricky, obj, 1, 4, *(int *)(*(int *)(tricky + 0x68)));
            }
        }
        if (*(u8 *)(state + 5) != 0) {
            Sfx_PlayFromObject(obj, SFXmv_mushdizzylp12);
            Sfx_PlayFromObject(obj, SFXmv_liftloop);
            *(u8 *)(state + 4) = 2;
            *(f32 *)(state + 0) = lbl_803E6DE4;
        }
    } else if (phase == 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x20)) != 0) {
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
            *(u8 *)(state + 4) = 1;
        }
    } else if (phase == 2) {
        f32 v = *(f32 *)(state + 0) + timeDelta;
        *(f32 *)(state + 0) = v;
        if (v >= lbl_803E6DE8) {
            *(u8 *)(state + 4) = 3;
        }
    } else if (phase == 3) {
        if (*(u16 *)(obj + 0xb0) & 0x800) {
            (*(void (**)(int, int, int, int, int, int))(*gPartfxInterface + 8))(obj, 1850, 0, 2, -1,
                                                                                0);
        }
        if (*(int *)(obj + 0xf4) == 0) {
            (*(void (**)(int, int))(*gObjectTriggerInterface + 0x54))(obj, 105);
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, 1);
        }
    }
    *(int *)(obj + 0xf4) = 1;
}
#pragma scheduling reset
#pragma peephole reset
