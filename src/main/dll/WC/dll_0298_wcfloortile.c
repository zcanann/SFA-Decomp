#include "main/dll/dll_80220608_shared.h"

#define SFXsc_strafe_active 198
#define SFXbaddie_rach_call3 675
#define SFXbaddie_rach_death 676

#pragma peephole on
#pragma scheduling on
int wcfloortile_getExtraSize(void) { return 8; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcfloortile_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcfloortile_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E98);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcfloortile_init(int obj)
{
    int state = *(int *)(obj + 0xb8);

    *(s16 *)obj = -0x4000;
    *(s16 *)(*(int *)(obj + 0x54) + 0x60) |= 0x1800;
    *(u8 *)(state + 7) |= 2;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcfloortile_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcfloortile_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    int setup = *(int *)(obj + 0x4c);

    if ((u32)GameBit_Get(824) != 0) {
        *(f32 *)(obj + 0x10) = *(f32 *)(setup + 0xc);
        *(u8 *)(state + 6) = 3;
    }
    switch (*(u8 *)(state + 6)) {
    case 0:
    default:
        if (*(u8 *)(state + 7) & 4) {
            f32 z = lbl_803E6E9C;
            int i, off;
            for (i = 0, off = 0; i < *(s8 *)(*(int *)(obj + 0x58) + 0x10f); i++, off += 4) {
                int e = *(int *)(*(int *)(obj + 0x58) + off + 0x100);
                if (*(s16 *)(e + 0x44) == 1) {
                    Sfx_PlayFromObject(obj, SFXsc_strafe_active);
                    *(u8 *)(state + 6) = 1;
                    *(f32 *)(state + 0) = z;
                    *(f32 *)(obj + 0x28) = z;
                }
            }
        } else if ((u32)GameBit_Get(613) != 0) {
            *(u8 *)(state + 7) |= 4;
        }
        break;
    case 1:
        *(f32 *)(state + 0) = *(f32 *)(state + 0) + timeDelta;
        if (*(f32 *)(state + 0) > lbl_803E6EA0) {
            *(u8 *)(state + 7) |= 3;
            *(f32 *)(state + 0) = lbl_803E6EA0;
            *(f32 *)(obj + 0x28) = lbl_803E6EA4 * timeDelta + *(f32 *)(obj + 0x28);
        }
        *(s16 *)(state + 4) = lbl_803E6EA8 * (*(f32 *)(state + 0) / lbl_803E6EA0);
        *(s16 *)(obj + 2) = (s16)randomGetRange(-*(s16 *)(state + 4), *(s16 *)(state + 4));
        *(s16 *)(obj + 4) = (s16)randomGetRange(-*(s16 *)(state + 4), *(s16 *)(state + 4));
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        {
            f32 d = *(f32 *)(setup + 0xc) - *(f32 *)(obj + 0x10);
            f32 t;
            if (d < lbl_803E6EAC) {
                t = lbl_803E6EB0;
            } else if (d > lbl_803E6EB4) {
                t = lbl_803E6E9C;
            } else {
                t = lbl_803E6E98 - (d - lbl_803E6EAC) / lbl_803E6EB8;
                if (t > lbl_803E6E98) {
                    t = lbl_803E6E98;
                } else if (t < lbl_803E6E9C) {
                    t = lbl_803E6E9C;
                }
                t = t * lbl_803E6EB0;
            }
            *(u8 *)(obj + 0x36) = (int)t;
        }
        if (*(u8 *)(obj + 0x36) == 0) {
            *(u8 *)(state + 6) = 2;
        }
        break;
    case 2:
        *(u8 *)(obj + 0x36) = 0;
        ObjHits_DisableObject(obj);
        *(u8 *)(state + 7) |= 3;
        break;
    case 3:
        {
            f32 a = lbl_803E6EBC * timeDelta + (f32)(u32) * (u8 *)(obj + 0x36);
            if (a > lbl_803E6EB0) {
                a = lbl_803E6EB0;
            }
            *(u8 *)(obj + 0x36) = (int)a;
        }
        ObjHits_EnableObject(obj);
        break;
    }
    {
        int setup2 = *(int *)(obj + 0x4c);
        if (fn_80065640() != 0) {
            *(u8 *)(state + 7) |= 2;
        }
        if (*(u8 *)(state + 7) & 2) {
            if (fn_80065640() == 0) {
                fn_80065574(*(s16 *)(setup2 + 0x1a), *(int *)(obj + 0x30), *(u8 *)(state + 7) & 1);
                *(u8 *)(state + 7) &= ~2;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022AE1C(int obj, int bounds) {
    f32 cx = *(f32 *)(bounds + 0x14);
    f32 hx = cx + *(f32 *)(bounds + 0x20);
    f32 lx = cx - *(f32 *)(bounds + 0x20);
    f32 cy = *(f32 *)(bounds + 0x18);
    f32 hy = cy + *(f32 *)(bounds + 0x28);
    f32 ly = cy - *(f32 *)(bounds + 0x24);
    if (*(f32 *)(obj + 0xc) > hx) {
        *(f32 *)(obj + 0xc) = hx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    } else if (*(f32 *)(obj + 0xc) < lx) {
        *(f32 *)(obj + 0xc) = lx;
        *(f32 *)(bounds + 0x48) = lbl_803E6ECC;
    }
    if (*(f32 *)(obj + 0x10) > hy) {
        *(f32 *)(obj + 0x10) = hy;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    } else if (*(f32 *)(obj + 0x10) < ly) {
        *(f32 *)(obj + 0x10) = ly;
        *(f32 *)(bounds + 0x4c) = lbl_803E6ECC;
    }
    *(f32 *)(bounds + 0x2c) = *(f32 *)(obj + 0xc) - *(f32 *)(bounds + 0x14);
    *(f32 *)(bounds + 0x30) = *(f32 *)(obj + 0x10) - *(f32 *)(bounds + 0x18);
    *(f32 *)(bounds + 0x34) = lbl_803E6ECC;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022AECC(int obj, int p)
{
    f32 v[3];
    f32 cz;
    int diff;
    int iv;

    if (*(s8 *)(p + 0xac) == 0x26) {
        *(f32 *)(p + 0x44) = lbl_803E6ECC;
    }
    PSVECSubtract((void *)(p + 0x3c), (void *)(p + 0x48), v);
    v[0] = v[0] * *(f32 *)(p + 0x60);
    v[1] = v[1] * *(f32 *)(p + 0x64);
    v[2] = v[2] * *(f32 *)(p + 0x68);
    if (v[2] < *(f32 *)(p + 0x84)) {
        cz = *(f32 *)(p + 0x84);
    } else if (v[2] > *(f32 *)(p + 0x78)) {
        cz = *(f32 *)(p + 0x78);
    } else {
        cz = v[2];
    }
    v[2] = cz;
    PSVECScale(v, v, timeDelta);
    PSVECAdd((int)(p + 0x48), (int)v, (int)(p + 0x48));
    objMove(obj, *(f32 *)(p + 0x48) * timeDelta, *(f32 *)(p + 0x4c) * timeDelta,
            *(f32 *)(p + 0x50) * timeDelta);

    diff = *(int *)(p + 0x340) - (u16) * (int *)(p + 0x344);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x34c)) - *(int *)(p + 0x350));
    if (iv < -0x32) iv = -0x32;
    else if (iv > 0x32) iv = 0x32;
    *(int *)(p + 0x350) = (int)((f32)iv * timeDelta + (f32) * (int *)(p + 0x350));
    *(int *)(p + 0x344) =
        (int)((f32) * (int *)(p + 0x350) * timeDelta + (f32) * (int *)(p + 0x344));

    diff = *(int *)(p + 0x354) - (u16) * (int *)(p + 0x358);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)(f32)((int)((f32)diff * *(f32 *)(p + 0x360)) - *(int *)(p + 0x364));
    if (iv < -0x32) iv = -0x32;
    else if (iv > 0x32) iv = 0x32;
    *(int *)(p + 0x364) = (int)((f32)iv * timeDelta + (f32) * (int *)(p + 0x364));
    *(int *)(p + 0x358) =
        (int)((f32) * (int *)(p + 0x364) * timeDelta + (f32) * (int *)(p + 0x358));

    diff = *(int *)(p + 0x368) - (u16) * (int *)(p + 0x36c);
    if (diff > 0x8000) diff -= 0xffff;
    if (diff < -0x8000) diff += 0xffff;
    iv = (int)((f32)(int)((f32)diff * *(f32 *)(p + 0x374)) - *(f32 *)(p + 0x378));
    if (iv < -0x64) iv = -0x64;
    else if (iv > 0x64) iv = 0x64;
    *(f32 *)(p + 0x378) = (f32)iv * timeDelta + *(f32 *)(p + 0x378);
    *(int *)(p + 0x36c) =
        (int)(*(f32 *)(p + 0x378) * timeDelta + (f32) * (int *)(p + 0x36c));

    if (*(u8 *)(p + 0x478) == 0) {
        diff = *(int *)(p + 0x37c) - (u16) * (int *)(p + 0x380);
        if (diff > 0x8000) diff -= 0xffff;
        if (diff < -0x8000) diff += 0xffff;
        *(int *)(p + 0x380) =
            (int)(timeDelta * ((f32)diff * *(f32 *)(p + 0x388)) + (f32) * (int *)(p + 0x380));
        if ((f32) * (int *)(p + 0x380) > *(f32 *)(p + 0x394) ||
            (f32) * (int *)(p + 0x380) < -*(f32 *)(p + 0x394)) {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
        } else {
            *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x390) * timeDelta + *(f32 *)(p + 0x38c);
        }
    } else {
        *(f32 *)(p + 0x38c) = *(f32 *)(p + 0x38c) - *(f32 *)(p + 0x390) * timeDelta;
    }
    if (*(f32 *)(p + 0x38c) < lbl_803E6ECC) {
        *(f32 *)(p + 0x38c) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x38c) > lbl_803E6ED0) {
        *(f32 *)(p + 0x38c) = lbl_803E6ED0;
    }

    *(s16 *)(obj + 0) = (s16) * (int *)(p + 0x344);
    *(s16 *)(obj + 2) = (s16) * (int *)(p + 0x358);
    if (*(u8 *)(p + 0x478) == 1) {
        fn_8022AB68(obj, p);
    } else {
        *(s16 *)(obj + 4) = (s16)(int)((f32) * (int *)(p + 0x36c) * *(f32 *)(p + 0x38c) +
                                        (f32) * (int *)(p + 0x380));
        if (*(s16 *)(obj + 4) < -0x4000) {
            *(s16 *)(obj + 4) = -0x4000;
        } else if (*(s16 *)(obj + 4) > 0x4000) {
            *(s16 *)(obj + 4) = 0x4000;
        }
    }

    if (sqrtf(*(f32 *)(p + 0x48) * *(f32 *)(p + 0x48) +
              *(f32 *)(p + 0x4c) * *(f32 *)(p + 0x4c)) < *(f32 *)(p + 0x3b4) &&
        *(u8 *)(p + 0x478) == 0) {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3e0) * timeDelta + *(f32 *)(p + 0x3dc);
    } else {
        *(f32 *)(p + 0x3dc) = *(f32 *)(p + 0x3dc) - *(f32 *)(p + 0x3e0) * timeDelta;
    }
    if (*(f32 *)(p + 0x3dc) < lbl_803E6ECC) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ECC;
    } else if (*(f32 *)(p + 0x3dc) > lbl_803E6ED0) {
        *(f32 *)(p + 0x3dc) = lbl_803E6ED0;
    }

    *(s16 *)(obj + 4) = (s16)(int)(*(f32 *)(p + 0x3dc) *
                                       (*(f32 *)(p + 0x3bc) *
                                        fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3c0) /
                                                    lbl_803E6F00)) +
                                   (f32) * (s16 *)(obj + 4));
    *(f32 *)(obj + 0xc) =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3c8) *
             fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3cc) / lbl_803E6F00)) +
        *(f32 *)(obj + 0xc);
    *(f32 *)(obj + 0x10) =
        *(f32 *)(p + 0x3dc) *
            (*(f32 *)(p + 0x3d4) *
             fn_80293E80(lbl_803E6EFC * (f32)(u32) * (u16 *)(p + 0x3d8) / lbl_803E6F00)) +
        *(f32 *)(obj + 0x10);
    *(u16 *)(p + 0x3c0) =
        (u16)(int)(*(f32 *)(p + 0x3b8) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3c0));
    *(u16 *)(p + 0x3cc) =
        (u16)(int)(*(f32 *)(p + 0x3c4) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3cc));
    *(u16 *)(p + 0x3d8) =
        (u16)(int)(*(f32 *)(p + 0x3d0) * timeDelta + (f32)(u32) * (u16 *)(p + 0x3d8));
    fn_8022AE1C(obj, p);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022B8A0(int p, int q) {
    if (*(void **)(q + 0x438) != NULL)
        return;
    {
        f32 t = *(f32 *)(q + 0x440);
        if (t > lbl_803E6ECC) {
            *(f32 *)(q + 0x440) = t - timeDelta;
            if (*(f32 *)(q + 0x440) >= lbl_803E6ECC)
                return;
            *(f32 *)(q + 0x440) = lbl_803E6ECC;
        }
    }
    if (*(u16 *)(q + 0x3f4) & 0x200) {
        if ((s8) * (u8 *)(q + 0x43c) == 1) {
            fn_8022B764(p, q, 0);
            fn_8022B764(p, q, 1);
        } else {
            fn_8022B764(p, q, *(u8 *)(q + 0x43d));
            *(u8 *)(q + 0x43d) = (*(u8 *)(q + 0x43d) ^ 1) & 0xff;
        }
        *(f32 *)(q + 0x440) = (f32)(u32) * (u16 *)(q + 0x444);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void fn_8022B764(int p, int q, int idx) {
    f32 pz, py, px;
    int setup;
    u8 cnt;
    if (Obj_IsLoadingLocked() == 0)
        return;
    cnt = *(u8 *)(q + 0x44c);
    if (cnt == 0)
        return;
    *(u8 *)(q + 0x44c) = cnt - 1;
    if (idx == 0)
        ObjPath_GetPointWorldPosition(p, 5, &px, &py, &pz, 0);
    else
        ObjPath_GetPointWorldPosition(p, 6, &px, &py, &pz, 0);
    setup = Obj_AllocObjectSetup(0x20, 0x605);
    *(f32 *)(setup + 8) = px;
    *(f32 *)(setup + 0xc) = py;
    *(f32 *)(setup + 0x10) = pz;
    *(u8 *)(setup + 0x1a) = *(s16 *)(p + 0) >> 8;
    *(u8 *)(setup + 0x19) = *(s16 *)(p + 2) >> 8;
    *(u8 *)(setup + 0x18) = *(s16 *)(p + 4) >> 8;
    *(u8 *)(setup + 4) = 1;
    *(u8 *)(setup + 5) = 1;
    *(int *)(q + 0x438) = loadObjectAtObject(p);
    fn_8022ED74(*(int *)(q + 0x438), *(u16 *)(q + 0x446));
    fn_8022ECE0(*(int *)(q + 0x438), *(f32 *)(q + 0x448));
    Sfx_PlayFromObject(p, SFXbaddie_rach_call3);
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void fn_8022A9C8(int obj, int state)
{
    int slot;
    f32 mtx[12];
    ArwProjPosSrc src;

    slot = Camera_GetCurrentViewSlot();
    src.pos[0] = *(f32 *)(obj + 0xc);
    src.pos[1] = *(f32 *)(obj + 0x10);
    src.pos[2] = *(f32 *)(obj + 0x14);
    src.rot[0] = *(s16 *)obj;
    src.rot[1] = *(s16 *)(obj + 2);
    src.rot[2] = 0;
    src.scale = lbl_803E6ED0;
    setMatrixFromObjectPos(mtx, &src);

    Matrix_TransformPoint(mtx, lbl_803E6ECC, lbl_803E6ECC, lbl_803E6EF0,
                          (f32 *)(*(int *)(state + 0x418) + 0xc),
                          (f32 *)(*(int *)(state + 0x418) + 0x10),
                          (f32 *)(*(int *)(state + 0x418) + 0x14));
    *(f32 *)(*(int *)(state + 0x418) + 0x18) = *(f32 *)(*(int *)(state + 0x418) + 0xc);
    *(f32 *)(*(int *)(state + 0x418) + 0x1c) = *(f32 *)(*(int *)(state + 0x418) + 0x10);
    *(f32 *)(*(int *)(state + 0x418) + 0x20) = *(f32 *)(*(int *)(state + 0x418) + 0x14);
    *(s16 *)(*(int *)(state + 0x418) + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(*(int *)(state + 0x418) + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(*(int *)(state + 0x418) + 0) = 0x8000 - *(s16 *)slot;

    Matrix_TransformPoint(mtx, lbl_803E6ECC, lbl_803E6ECC, lbl_803E6EF4,
                          (f32 *)(*(int *)(state + 0x41c) + 0xc),
                          (f32 *)(*(int *)(state + 0x41c) + 0x10),
                          (f32 *)(*(int *)(state + 0x41c) + 0x14));
    *(f32 *)(*(int *)(state + 0x41c) + 0x18) = *(f32 *)(*(int *)(state + 0x41c) + 0xc);
    *(f32 *)(*(int *)(state + 0x41c) + 0x1c) = *(f32 *)(*(int *)(state + 0x41c) + 0x10);
    *(f32 *)(*(int *)(state + 0x41c) + 0x20) = *(f32 *)(*(int *)(state + 0x41c) + 0x14);
    *(s16 *)(*(int *)(state + 0x41c) + 4) = -*(s16 *)(slot + 4);
    *(s16 *)(*(int *)(state + 0x41c) + 2) = -*(s16 *)(slot + 2);
    *(s16 *)(*(int *)(state + 0x41c) + 0) = 0x8000 - *(s16 *)slot;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022A670(int obj, int state)
{
    f32 nx;
    f32 ny;
    f32 tv;
    int btn;

    debugPrintSetColor(0xff, 0xff, 0xff, 0xff);
    *(f32 *)(state + 0x3e4) = (f32)(s8)padGetStickX(0) / lbl_803E6EC8;
    *(f32 *)(state + 0x3e8) = (f32)(s8)padGetStickY(0) / lbl_803E6EC8;
    if (*(f32 *)(state + 0x328) > lbl_803E6ECC) {
        nx = -*(f32 *)(state + 0x32c);
        ny = -*(f32 *)(state + 0x330);
        *(f32 *)(state + 0x328) = *(f32 *)(state + 0x328) - timeDelta;
        tv = lbl_8032B4A8[(int)*(f32 *)(state + 0x328)];
        if (*(f32 *)(state + 0x328) <= lbl_803E6ECC) {
            *(u8 *)(state + 0x338) = 0;
            (*(void (**)(int, int))(*gPathControlInterface + 0x20))(obj, state + 0xc0);
        }
        *(f32 *)(state + 0x3e4) =
            *(f32 *)(state + 0x3e4) * (lbl_803E6ED0 - tv) + nx * tv;
        *(f32 *)(state + 0x3e8) =
            *(f32 *)(state + 0x3e8) * (lbl_803E6ED0 - tv) + ny * tv;
    }
    *(f32 *)(state + 0x3ec) = (f32)(u32)(u8)padGetRTrigger(0) / lbl_803E6ED4;
    if (*(f32 *)(state + 0x3ec) < lbl_803E6ECC)
        *(f32 *)(state + 0x3ec) = lbl_803E6ECC;
    else if (*(f32 *)(state + 0x3ec) > lbl_803E6ED0)
        *(f32 *)(state + 0x3ec) = lbl_803E6ED0;
    *(f32 *)(state + 0x3f0) = -(f32)(u32)(u8)padGetLTrigger(0) / lbl_803E6ED4;
    if (*(f32 *)(state + 0x3f0) < lbl_803E6ED8)
        *(f32 *)(state + 0x3f0) = lbl_803E6ED8;
    else if (*(f32 *)(state + 0x3f0) > lbl_803E6ECC)
        *(f32 *)(state + 0x3f0) = lbl_803E6ECC;
    *(u16 *)(state + 0x3f4) = (u16)getButtonsJustPressed(0);
    *(u16 *)(state + 0x3f6) = (u16)getButtonsJustPressedIfNotBusy(0);
    *(u16 *)(state + 0x3f8) = (u16)getButtonsHeld(0);
    if (*(u8 *)(state + 0x478) == 0) {
        btn = *(u16 *)(state + 0x3f4);
        if ((btn & 0x20) != 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            *(u8 *)(state + 0x478) = 1;
            *(int *)(state + 0x398) = *(s16 *)(obj + 4);
            *(f32 *)(state + 0x3a0) = *(f32 *)(state + 0x39c);
            *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) * *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) * *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 1, 0);
        } else if ((btn & 0x40) != 0) {
            Sfx_PlayFromObject(obj, SFXbaddie_rach_death);
            *(u8 *)(state + 0x478) = 1;
            *(int *)(state + 0x398) = *(s16 *)(obj + 4);
            *(f32 *)(state + 0x3a0) = -*(f32 *)(state + 0x39c);
            *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) * *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) * *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 1, 1);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void fn_8022AB68(int obj, int state)
{
    int tgt;
    int cur;
    int d;

    *(int *)(state + 0x398) =
        (int)(timeDelta * (*(f32 *)(state + 0x3a0) * *(f32 *)(state + 0x3a8)) +
              (f32) * (int *)(state + 0x398));
    *(s16 *)(obj + 4) =
        (s16)(int)(timeDelta * (*(f32 *)(state + 0x3a0) * *(f32 *)(state + 0x3a8)) +
                   (f32) * (s16 *)(obj + 4));
    if (*(f32 *)(state + 0x3a0) > lbl_803E6ECC) {
        tgt = *(int *)(state + 0x380);
        cur = *(int *)(state + 0x398);
        if (cur > tgt + 0xffff) {
            *(u8 *)(state + 0x478) = 0;
            *(int *)(state + 0x380) = *(int *)(state + 0x398) - 0xffff;
            *(f32 *)(state + 0x38c) = lbl_803E6ECC;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) / *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) / *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        } else if (cur > tgt + 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            *(f32 *)(state + 0x3a8) = (f32)d / *(f32 *)(state + 0x3a4);
            if (*(f32 *)(state + 0x3a8) < lbl_803E6EF8)
                *(f32 *)(state + 0x3a8) = lbl_803E6EF8;
            else if (*(f32 *)(state + 0x3a8) > lbl_803E6ED0)
                *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
        }
    } else {
        tgt = *(int *)(state + 0x380);
        cur = *(int *)(state + 0x398);
        if (cur < tgt - 0xffff) {
            *(u8 *)(state + 0x478) = 0;
            *(int *)(state + 0x380) = *(int *)(state + 0x398) + 0xffff;
            *(f32 *)(state + 0x38c) = lbl_803E6ECC;
            *(f32 *)(state + 0x54) = *(f32 *)(state + 0x54) / *(f32 *)(state + 0x3ac);
            *(f32 *)(state + 0x60) = *(f32 *)(state + 0x60) / *(f32 *)(state + 0x3b0);
            arwarwingbo_setActiveVisible(*(int *)(state + 0x10), 0, 0);
        } else if (cur > tgt - 0x8000) {
            d = cur - (u16)tgt;
            if (d > 0x8000) d -= 0xffff;
            if (d < -0x8000) d += 0xffff;
            if (d < 0) d = -d;
            *(f32 *)(state + 0x3a8) = (f32)d / *(f32 *)(state + 0x3a4);
            if (*(f32 *)(state + 0x3a8) < lbl_803E6EF8)
                *(f32 *)(state + 0x3a8) = lbl_803E6EF8;
            else if (*(f32 *)(state + 0x3a8) > lbl_803E6ED0)
                *(f32 *)(state + 0x3a8) = lbl_803E6ED0;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
