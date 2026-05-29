#include "main/dll/dll_80220608_shared.h"

#pragma peephole on
#pragma scheduling on
int directionallight_getExtraSize(void) { return 0x10; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int directionallight_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void directionallight_free(int obj)
{
    int state = *(int *)(obj + 0xb8);
    if (*(void **)(state + 8) != NULL) {
        ModelLightStruct_free(*(void **)(state + 8));
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void directionallight_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void directionallight_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7254);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void directionallight_debugEdit(int obj, int state)
{
    u8 *desc = gDirectionalLightObjDescriptor;
    u16 buttons = (u16)getButtonsJustPressed(0);

    if ((buttons & 0x10) != 0) {
        *(u8 *)(state + 0xc) ^= 1;
    }
    if (*(u8 *)(state + 0xc) == 0) {
        return;
    }
    if ((buttons & 8) != 0) {
        *(u8 *)(state + 0xd) += 1;
    }
    if ((buttons & 4) != 0) {
        *(u8 *)(state + 0xd) -= 1;
    }
    if ((s8)*(u8 *)(state + 0xd) >= 8) {
        *(u8 *)(state + 0xd) = 0;
    }
    if ((s8)*(u8 *)(state + 0xd) < 0) {
        *(u8 *)(state + 0xd) = 7;
    }

    switch ((s8)*(u8 *)(state + 0xd)) {
    case 0:
        if ((buttons & 1) != 0) {
            *(s16 *)(obj + 0) -= 0x3e8;
        }
        if ((buttons & 2) != 0) {
            *(s16 *)(obj + 0) += 0x3e8;
        }
        fn_80137948(desc + 0x38);
        fn_80137948(desc + 0x44, *(s16 *)(obj + 0));
        break;
    case 1:
        if ((buttons & 1) != 0) {
            *(s16 *)(obj + 2) -= 0x3e8;
        }
        if ((buttons & 2) != 0) {
            *(s16 *)(obj + 2) += 0x3e8;
        }
        fn_80137948(desc + 0x50);
        fn_80137948(desc + 0x44, *(s16 *)(obj + 2));
        break;
    case 2:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 0) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 0) += 5;
        }
        fn_80137948(desc + 0x60);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 0));
        break;
    case 3:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 1) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 1) += 5;
        }
        fn_80137948(desc + 0x88);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 1));
        break;
    case 4:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 2) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 2) += 5;
        }
        fn_80137948(desc + 0xa4);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 2));
        break;
    case 5:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 4) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 4) += 5;
        }
        fn_80137948(desc + 0xc0);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 4));
        break;
    case 6:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 5) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 5) += 5;
        }
        fn_80137948(desc + 0xdc);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 5));
        break;
    case 7:
        if ((buttons & 1) != 0) {
            *(u8 *)(state + 6) -= 5;
        }
        if ((buttons & 2) != 0) {
            *(u8 *)(state + 6) += 5;
        }
        fn_80137948(desc + 0xfc);
        fn_80137948(desc + 0x7c, *(u8 *)(state + 6));
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void directionallight_init(int obj, int setup)
{
    u8 colorR, colorG, colorB;
    PointLightVec vec;
    int state = *(int *)(obj + 0xb8);

    vec = *(PointLightVec *)lbl_802C2608;

    *(s16 *)(obj + 0) = (s16)(*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(u8 *)(setup + 0x19) << 8);

    if (*(void **)(state + 8) == NULL) {
        *(void **)(state + 8) = objCreateLight(obj, 1);
    }

    if (*(void **)(state + 8) != NULL) {
        modelLightStruct_setField50(*(void **)(state + 8), 4);
        objSetEventName(*(void **)(state + 8), *(u8 *)(setup + 0x1d));
        modelStruct2_setVectors(*(void **)(state + 8), vec.x, vec.y, vec.z);

        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
            lightSetFieldB0(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
        } else {
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), *(u8 *)(setup + 0x1a),
                *(u8 *)(setup + 0x1b), *(u8 *)(setup + 0x1c), 0xff);
            lightSetFieldB0(*(void **)(state + 8), *(u8 *)(setup + 0x27),
                *(u8 *)(setup + 0x28), *(u8 *)(setup + 0x29), 0xff);
        }

        lightFn_8001db6c(*(void **)(state + 8), *(u8 *)(setup + 0x30), lbl_803E7250);
        *(u8 *)(state + 0xe) = *(u8 *)(setup + 0x30);
        lightFn_8001d620(*(void **)(state + 8), *(u8 *)(setup + 0x26), *(s16 *)(setup + 0x2e));

        if (*(u8 *)(setup + 0x2c) != 0) {
            fn_8001DB5C(*(void **)(state + 8), *(u8 *)(setup + 0x2c));
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void directionallight_update(int obj)
{
    u8 colorR, colorG, colorB;
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if (*(void **)(state + 8) == NULL) {
        return;
    }

    *(s16 *)(obj + 0) =
        (s16)((f32)*(s16 *)(setup + 0x32) * timeDelta + (f32)*(s16 *)(obj + 0));
    *(s16 *)(obj + 2) =
        (s16)((f32)*(s16 *)(setup + 0x34) * timeDelta + (f32)*(s16 *)(obj + 2));

    if (*(u8 *)(state + 0xe) != 0) {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) == 0) {
            *(u8 *)(state + 0xe) = 0;
            lightFn_8001db6c(*(void **)(state + 8), 0, lbl_803E7254);
        }
        if ((*(u8 *)(setup + 0x2a) & 1) != 0) {
            getAmbientColor(0, &colorR, &colorG, &colorB);
            modelLightStruct_setColorsA8AC(*(void **)(state + 8), colorR, colorG, colorB, 0xff);
        }
    } else {
        if ((u32)GameBit_Get(*(s16 *)(setup + 0x1e)) != 0) {
            *(u8 *)(state + 0xe) = 1;
            lightFn_8001db6c(*(void **)(state + 8), 1, lbl_803E7254);
        }
    }

    directionallight_debugEdit(obj, state);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void directionallight_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void directionallight_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
