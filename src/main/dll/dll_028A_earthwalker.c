#include "main/dll/dll_80220608_shared.h"
#include "main/mapEventTypes.h"

#pragma peephole on
#pragma scheduling on
int earthwalker_getExtraSize(void) { return 0x660; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int earthwalker_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void earthwalker_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void earthwalker_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int state = *(int *)(obj + 0xb8);

    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6CE0);
        dll_2E_func06(obj, state, 0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void earthwalker_hitDetect(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if (*(s16 *)(obj + 0xa0) == 0x203) {
        fn_8003AAE0(obj, seqFn_800394a0(), *(u8 *)(state + 0x610), 0, 0x186a0);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void earthwalker_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void earthwalker_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void earthwalker_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int prevAnim;
    int hitOut;

    hitOut = objHitReact_update(obj, gEarthWalkerHitReactEntries, 1, *(u8 *)(state + 0x65a), (f32 *)(state + 0x654));
    *(u8 *)(state + 0x65a) = hitOut;
    if ((u8)hitOut != 0) {
        return;
    }

    if (*(u8 *)(state + 0x65b) >= 4 && *(u8 *)(state + 0x65b) <= 8) {
        if (*(s16 *)(obj + 0xa0) != 0x203) {
            ObjAnim_SetCurrentMove(obj, 0x203, lbl_803E6CE4, 0);
        }
    } else {
        if (*(s16 *)(obj + 0xa0) != 2) {
            ObjAnim_SetCurrentMove(obj, 2, lbl_803E6CE4, 0);
        }
    }

    prevAnim = *(u8 *)(state + 0x600);
    dll_2E_func03(obj, state);
    if (*(u8 *)(state + 0x65b) >= 4 && *(u8 *)(state + 0x65b) <= 7 && prevAnim != 1 &&
        *(u8 *)(state + 0x600) == 1) {
        Sfx_PlayFromObject(obj, 0x3e6);
    }

    characterDoEyeAnims(obj, state + 0x624);
    if (*(u8 *)(state + 0x659) & 1) {
        return;
    }

    switch (*(u8 *)(state + 0x658)) {
    case 0:
        if (*(u8 *)(obj + 0xaf) & 1) {
            buttonDisable(0, 0x100);
            GameBit_Set(0x7fb, 1);
            *(u8 *)(state + 0x658) = 2;
            *(u8 *)(state + 0x659) |= 1;
        }
        break;
    case 1:
        break;
    case 2:
        if (*(u8 *)(obj + 0xaf) & 1) {
            int newState;
            switch (*(u8 *)(state + 0x65b)) {
            case 0:
                if (((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x14) {
                        newState = 0x15;
                    } else {
                        newState = 0x14;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 5;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 4;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 3;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 3;
                } else if (*(s8 *)(state + 0x65c) == 0) {
                    newState = 1;
                } else if (*(s8 *)(state + 0x65c) == 1) {
                    newState = 2;
                } else {
                    newState = 0;
                }
                break;
            case 9:
                if (((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x16) {
                        newState = 0x17;
                    } else {
                        newState = 0x16;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0xa;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 9;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 8;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 8;
                } else if (*(s8 *)(state + 0x65c) == 6) {
                    newState = 7;
                } else {
                    newState = 6;
                }
                break;
            case 10:
                if (((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x18) {
                        newState = 0x19;
                    } else if (*(s8 *)(state + 0x65c) == 0x19) {
                        newState = 0x1a;
                    } else if (*(s8 *)(state + 0x65c) == 0x1a) {
                        newState = 0x1b;
                    } else {
                        newState = 0x18;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0xf;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 0xe;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 0xd;
                } else if (GameBit_Get(0x7fc) != 0) {
                    if (*(s8 *)(state + 0x65c) == 0xb) {
                        newState = 0xc;
                    } else {
                        newState = 0xb;
                    }
                }
                break;
            case 11:
                if (((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
                    if (*(s8 *)(state + 0x65c) == 0x1c) {
                        newState = 0x1d;
                    } else if (*(s8 *)(state + 0x65c) == 0x1d) {
                        newState = 0x1e;
                    } else if (*(s8 *)(state + 0x65c) == 0x1e) {
                        newState = 0x1f;
                    } else {
                        newState = 0x1c;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 0x13;
                } else if (GameBit_Get(0xc36) != 0) {
                    if (*(s8 *)(state + 0x65c) == 0x11) {
                        newState = 0x12;
                    } else {
                        newState = 0x11;
                    }
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 0x10;
                } else if (GameBit_Get(0x7fc) != 0) {
                    newState = 0x10;
                }
                break;
            case 1:
                if (((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
                    if (GameBit_Get(0xc92) != 0) {
                        *(u8 *)(obj + 0xaf) |= 8;
                        newState = -1;
                    } else if (GameBit_Get(0x235) != 0) {
                        newState = 9;
                    } else {
                        newState = 8;
                    }
                } else if (GameBit_Get(0xc90) != 0) {
                    newState = 7;
                } else if (GameBit_Get(0xc36) != 0) {
                    newState = 6;
                } else if (GameBit_Get(0xc55) != 0) {
                    newState = 5;
                } else {
                    newState = 0;
                }
                break;
            case 3:
                newState = 0;
                break;
            case 2:
                newState = 0;
                break;
            case 4:
                newState = 0;
                break;
            case 5:
                newState = 1;
                break;
            case 6:
                newState = 2;
                break;
            case 7:
                newState = 3;
                break;
            case 8:
                if ((u32)GameBit_Get(0x9ad) == 0) {
                    newState = 4;
                    buttonDisable(0, 0x100);
                    GameBit_Set(0x9ad, 1);
                } else {
                    newState = 0;
                }
                break;
            }
            if (newState != -1) {
                buttonDisable(0, 0x100);
                (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(newState, obj, -1);
                *(s8 *)(state + 0x65c) = newState;
            }
        }
        break;
    }

    ObjAnim_AdvanceCurrentMove(lbl_803E6CDC, timeDelta, obj, 0);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_80223BBC(void) { return 0x2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int fn_80223D10(void) { return 0x2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_802239A4(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    int result;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 3);
        result = 0;
    } else if (*(s8 *)(ai + 0x346) != 0) {
        result = 3;
    } else {
        result = 0;
    }
    return result;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80223A1C(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    f32 dist;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) |= 1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 1);
    }
    *(f32 *)(state + 0xabc) -= timeDelta;
    dist = *(f32 *)(state + 0xab8);
    if (dist > lbl_803E6CF0) {
        return 2;
    }
    if (dist >= lbl_803E6CF4) {
        return 0;
    }
    if (*(f32 *)(state + 0xabc) <= lbl_803E6CF8) {
        *(f32 *)(state + 0xabc) = (f32)randomGetRange(0x78, 0xfa);
        return 4;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80223AFC(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);
    int curve = state + 0x9b0;

    if (*(s8 *)(ai + 0x27b) != 0) {
        *(u8 *)(state + 0xac0) &= ~1;
        (*(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, ai, 2);
    }
    if (curveFn_80010320(curve, lbl_803E6D08) != 0 || *(int *)(curve + 0x10) != 0) {
        (*(void (**)(int))(*gRomCurveInterface + 0x90))(curve);
    }
    if (*(f32 *)(state + 0xab8) < lbl_803E6D0C) {
        return 3;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80223BC4(int obj, int ai)
{
    int player = Obj_GetPlayerObject();

    if (*(s8 *)(ai + 0x27a) != 0) {
        *(f32 *)(ai + 0x2a0) = lbl_803E6D10;
        getAngle(*(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc),
                 *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14));
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80223C34(int obj, int ai)
{
    int state = *(int *)(obj + 0xb8);

    *(f32 *)(obj + 0x24) = oneOverTimeDelta * (*(f32 *)(state + 0xa18) - *(f32 *)(obj + 0xc));
    *(f32 *)(obj + 0x2c) = oneOverTimeDelta * (*(f32 *)(state + 0xa20) - *(f32 *)(obj + 0x14));
    *(f32 *)(obj + 0xc) = *(f32 *)(state + 0xa18);
    *(f32 *)(obj + 0x14) = *(f32 *)(state + 0xa20);
    *(s16 *)obj = getAngle(-*(f32 *)(state + 0xa24), -*(f32 *)(state + 0xa2c));
    ObjAnim_SampleRootCurvePhase(
        sqrtf(*(f32 *)(obj + 0x24) * *(f32 *)(obj + 0x24) +
              *(f32 *)(obj + 0x2c) * *(f32 *)(obj + 0x2c)),
        (ObjAnimComponent *)obj, (f32 *)(ai + 0x2a0));
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int fn_80223CF0(int obj, int ai)
{
    if (*(s8 *)(ai + 0x27a) != 0) {
        *(f32 *)(ai + 0x2a0) = lbl_803E6D14;
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int earthwalker_animEventCallback(int obj, int p2, int p3, int p4)
{
    int state = *(int *)(obj + 0xb8);
    int i;

    *(u8 *)(state + 0x659) &= ~1;
    characterDoEyeAnims(obj, state + 0x624);
    if (dll_2E_func07(obj, p3, state, 0, 0) != 0) {
        return 0;
    }
    if ((s8)p4 != 0) {
        ObjAnim_AdvanceCurrentMove(lbl_803E6CDC, timeDelta, obj, 0);
    }
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(u8 *)(p3 + i + 0x81)) {
        case 1:
            getEnvfxActImmediately(obj, obj, 509, 0);
            break;
        case 2:
            getEnvfxActImmediately(obj, obj, 512, 0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void earthwalker_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);
    int local;

    local = lbl_803E6CD8;
    *(int *)(obj + 0xbc) = (int)earthwalker_animEventCallback;
    dll_2E_func05(obj, state, -8192, 12743, 2);
    dll_2E_func09(state, 0, &local, 2);
    fn_80113F94(state, lbl_803E6CE8);
    *(u8 *)(state + 0x611) |= 2;
    *(s16 *)obj = (s16)((s8)*(s8 *)(setup + 0x18) << 8);
    *(u8 *)(state + 0x65b) = *(u8 *)(setup + 0x19);
    if (*(u8 *)(state + 0x65b) == 1) {
        if (GameBit_Get(0x7fc) != 0 ||
            ((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac)) == 2) {
            *(u8 *)(state + 0x658) = 2;
        } else {
            *(u8 *)(state + 0x658) = 0;
        }
    } else {
        *(u8 *)(state + 0x658) = 2;
    }
    *(s8 *)(state + 0x65c) = -1;
}
#pragma scheduling reset
#pragma peephole reset
