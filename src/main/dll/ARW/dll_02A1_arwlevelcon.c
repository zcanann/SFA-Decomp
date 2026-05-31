#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int arwlevelcon_getExtraSize(void) { return 0x24; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwlevelcon_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwlevelcon_free(void)
{
    arwingHudSetVisible(2);
    fn_80125D04();
    setIsOvercast(1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E70E0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwlevelcon_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwlevelcon_commitRingChoice(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(u8 *)(state + 0x1b) != 0) {
        Music_Trigger(0xf3, 1);
    } else {
        Music_Trigger(2, 1);
    }
    arwingHudSetVisible(1);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwlevelcon_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void arwlevelcon_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void arwlevelcon_init(int obj, u8 *setup)
{
    int state = *(int *)(obj + 0xb8);

    *(int *)(obj + 0xbc) = (int)arwlevelcon_ringEventCallback;
    *(s16 *)(state + 0x14) = 1;
    *(s16 *)(state + 0x16) = 0x50;
    *(f32 *)(state + 0) = lbl_803E70EC;
    *(f32 *)(state + 4) = lbl_803E70EC;
    *(f32 *)(state + 8) = lbl_803E70F0;
    *(f32 *)(state + 0xc) = lbl_803E70F4;
    if (*(int *)(setup + 0x14) == 0x48f7e) {
        *(u8 *)(state + 0x1b) = 1;
    }
    if (*(u8 *)(state + 0x19) == 0) {
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
        GameBit_Set(0xe74, 0);
    }
    arwingHudSetVisible(2);
    pauseMenuCreateHeads();
    switch (*(s8 *)(obj + 0xac)) {
    case 0x3a:
        *(int *)(state + 0x1c) = 0x51bc;
        *(s16 *)(state + 0x20) = 0x6e3;
        break;
    case 0x3b:
        *(int *)(state + 0x1c) = 0x51bd;
        *(s16 *)(state + 0x20) = 0x6df;
        break;
    case 0x3d:
        *(int *)(state + 0x1c) = 0x51bf;
        *(s16 *)(state + 0x20) = 0x6e2;
        break;
    case 0x3c:
        *(int *)(state + 0x1c) = 0x51be;
        *(s16 *)(state + 0x20) = 0x6e1;
        break;
    default:
        *(int *)(state + 0x1c) = 0x51c0;
        *(s16 *)(state + 0x20) = 0x6e0;
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int arwlevelcon_ringEventCallback(int obj, int p2, int data)
{
    int i;
    int textId;

    *(int *)(data + 0xe8) = (int)arwlevelcon_commitRingChoice;
    for (i = 0; i < *(u8 *)(data + 0x8b); i++) {
        u8 v = *(u8 *)(data + i + 0x81);
        if (v == 1) {
            (*(void (**)(int, int, int, int))(*gObjectTriggerInterface + 0x50))(0x56, 0, 0, 0);
        } else if (v == 4) {
            switch (*(s8 *)(obj + 0xac)) {
            case 0x3a:
                textId = 0;
                break;
            case 0x3b:
                textId = 1;
                break;
            case 0x3c:
                textId = 2;
                break;
            case 0x3e:
                textId = 3;
                break;
            case 0x3d:
                textId = 4;
                break;
            }
            gameTextFn_80125ba4(textId);
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void arwlevelcon_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int arwing = getArwing();

    if (*(u8 *)(state + 0x18) == 0) {
        skyFn_80089710(7, 1, 0);
        if (*(u8 *)(state + 0x1b) != 0) {
            skyFn_800895e0(7, 0xaa, 0x78, 0xff, 0x69, 0x40);
        } else {
            skyFn_800895e0(7, 0x96, 0x64, 0xf0, 0, 0);
        }
        skyFn_800894a8(7, lbl_803E70E4, lbl_803E70E4, lbl_803E70E0);
        getEnvfxAct(0, 0, 0x21f, 0);
        getEnvfxAct(0, 0, 0x22b, 0);
        setIsOvercast(0);
        *(u8 *)(state + 0x18) = 1;
        setDrawLights(0);
    }
    if (*(u8 *)(state + 0x19) == 0) {
        int mode;
        if (*(u8 *)(state + 0x1b) != 0) {
            mode = 3;
        } else {
            if (AudioStream_IsPreparing() == 0) {
                AudioStream_Play(*(int *)(state + 0x1c), AudioStream_StartPrepared);
            }
            mode = 0;
        }
        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(mode, obj, -1);
        *(u8 *)(state + 0x19) = 1;
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
    }
    if (*(u8 *)(state + 0x1a) == 0) {
        int mb = mapBlockFn_800592e4();
        if (*(f32 *)(arwing + 0x14) - *(f32 *)(mb + 0x28) > lbl_803E70E8 &&
            fn_8022D750(arwing) == 0 && fn_8022D710(arwing) == 0) {
            int a, b;
            arwingHudSetVisible(2);
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x7c))(*(u16 *)(state + 0x20), 0, 0);
            a = arwarwing_getRequiredRingCount(arwing);
            b = arwarwing_getCollectedRingCount(arwing);
            if (b >= a) {
                GameBit_Set(0x9d8, 1);
            } else {
                GameBit_Set(0x9d7, 1);
            }
            *(u8 *)(state + 0x1a) = 1;
            Music_Trigger(2, 0);
            Music_Trigger(0xf3, 0);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
