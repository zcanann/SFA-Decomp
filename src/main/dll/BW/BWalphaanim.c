#include "ghidra_import.h"
#include "main/dll/BW/BWalphaanim.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 FUN_8000680c();
extern char FUN_80006bc8();
extern char FUN_80006bd0();
extern uint FUN_80006bf8();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a10();
extern undefined4 FUN_80017a80();
extern int FUN_80053c14();
extern undefined4 FUN_80053c20();
extern undefined4 FUN_8011e844();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_801ea854();
extern uint FUN_801eb0c0();
extern undefined4 fn_801EAE4C();
extern undefined4 fn_801EB0D4();
extern undefined4 fn_801EB634();
extern void fn_801EC1AC(int obj,int state);
extern undefined4 FUN_801ec7a0();
extern undefined4 FUN_801ecd30();
extern undefined4 FUN_80247e94();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80293130();

extern f64 DOUBLE_803e6798;
extern f64 DOUBLE_803e68b8;
extern f32 lbl_803DC074;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E6838;
extern f32 lbl_803E68B0;

extern void textureFree(u32);
extern u32 textureLoadAsset(int);
extern u32 lbl_803DDC60;

#pragma scheduling off
#pragma peephole off
void SnowBike_release(void) {
    if (lbl_803DDC60 != 0) {
        textureFree(lbl_803DDC60);
        lbl_803DDC60 = 0;
    }
}
void SnowBike_initialise(void) {
    if (lbl_803DDC60 == 0) {
        lbl_803DDC60 = textureLoadAsset(0x186);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma peephole off
void SB_CloudRunner_onSeqFree(int *obj) {
    int *p = (int*)obj[0xb8/4];
    *(f32*)((char*)p + 0x4c) = *(f32*)((char*)obj + 0xc);
    *(f32*)((char*)p + 0x50) = *(f32*)((char*)obj + 0x10);
    *(f32*)((char*)p + 0x54) = *(f32*)((char*)obj + 0x14);
    {
        s32 v = *(s16*)obj - 0x4000;
        *(s16*)((char*)p + 0x2c) = (s16)v;
    }
    *(s16*)((char*)p + 0x2e) = *(s16*)((char*)obj + 4);
}
#pragma peephole reset

extern char lbl_803284E0[];
extern u32 lbl_803E5AE0;
extern u8 *mmAlloc(int size, int tag, int a);
extern void *memcpy(void *dst, const void *src, int n);
extern void Obj_ClearModelSlotIndex(int obj);
extern void fn_801EC928(int obj, u8 *state);
extern void fn_801EB420();
extern void ObjGroup_AddObject(int obj, int group);
extern void curves_setLocalPointCollisionEx(u8 *path, int a, u8 *b, f32 *c, int d, int e);
extern int *gGameUIInterface;
extern int *gPathControlInterface;
extern f32 lbl_803DC0B8;
extern f32 lbl_803DC0C0;
extern f32 lbl_803DC0C4;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF0;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B48;
extern f32 lbl_803E5B74;
extern f32 lbl_803E5B90;
extern f32 lbl_803E5B94;
extern f32 lbl_803E5B98;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5C48;
extern f32 lbl_803E5C50;
extern f32 lbl_803E5C54;
extern f32 lbl_803E5C58;
extern f32 lbl_803E5C5C;
extern f32 lbl_803E5C60;
extern f32 lbl_803E5C64;
extern f32 lbl_803E5C68;

typedef struct {
    u8 pad0 : 2;
    u8 b20 : 1;
    u8 pad1 : 2;
    u8 b04 : 1;
    u8 b02 : 1;
    u8 b01 : 1;
} SnowBikeFlags;

void SnowBike_init(int obj, u8 *params, int flag)
{
    char *base = lbl_803284E0;
    u32 pathParam = lbl_803E5AE0;
    u8 *state = *(u8 **)(obj + 0xb8);
    u8 *alloc;
    u8 *path;
    int i;
    s16 rot;
    f32 fz;
    f32 fv;

    if (*(s8 *)(obj + 0xac) == 0x13) {
        alloc = mmAlloc(36, 5, 0);
        memcpy(alloc, params, 36);
        *(u8 **)(obj + 0x4c) = alloc;
        *(s16 *)(obj + 6) |= 0x2000;
        Obj_ClearModelSlotIndex(obj);
    }
    rot = params[0x18] << 8;
    *(s16 *)(state + 0x40c) = rot;
    *(s16 *)(state + 0x40e) = rot;
    *(s16 *)obj = rot;
    fn_801EC928(obj, state);
    if (flag == 0) {
        if (((SnowBikeFlags *)(state + 0x428))->b20) {
            *(f32 *)(state + 0x4b8) = lbl_803E5B90;
            *(f32 *)(state + 0x4c0) = lbl_803E5AEC;
            *(f32 *)(state + 0x4bc) = lbl_803E5B94;
            if (*(s8 *)(state + 0x421) == 2) {
                (**(void (**)(int, int))(*gGameUIInterface + 0x58))((int)*(f32 *)(state + 0x4b8), 1485);
                (**(void (**)(f32))(*gGameUIInterface + 0x68))(lbl_803E5B98);
            }
        }
    }
    if (params[0x19] != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b02 = 1;
    }
    *(int *)(state + 0x38) = -1;
    *(int *)(state + 0x3c) = -1;
    *(int *)(state + 0x40) = -1;
    state[0x5c] = params[0x1c];
    state[0x5d] = params[0x1d];
    *(f32 *)(state + 0xc) = *(f32 *)(obj + 0xc);
    *(f32 *)(state + 0x10) = *(f32 *)(obj + 0x10);
    *(f32 *)(state + 0x14) = *(f32 *)(obj + 0x14);
    *(int *)(obj + 0xbc) = (int)fn_801EB420;
    ObjGroup_AddObject(obj, 10);
    if (flag == 0) {
        i = 0;
        for (path = state; i < 9; i++) {
            *(u8 **)(path + 0x4c8) = mmAlloc(1600, 26, 0);
            path += 8;
        }
    }
    *(f32 *)(state + 0x51c) = *(f32 *)(obj + 0x18);
    *(f32 *)(state + 0x520) = *(f32 *)(obj + 0x1c);
    *(f32 *)(state + 0x524) = *(f32 *)(obj + 0x20);
    *(f32 *)(state + 0x68) = lbl_803E5AE8;
    *(s16 *)(state + 0x448) = *(s16 *)(params + 0x1a);
    *(s16 *)(state + 0x44a) = *(s16 *)(params + 0x1e);
    if (GameBit_Get(*(s16 *)(state + 0x44a)) != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b04 = 1;
    }
    *(f32 *)(state + 0x438) = lbl_803E5B1C;
    fz = lbl_803E5AE8;
    *(f32 *)(state + 0x3f4) = fz;
    *(f32 *)(state + 0x3f8) = fz;
    *(f32 *)(state + 0x18) = lbl_803E5C48;
    *(f32 *)(state + 0x1c) = fz;
    *(f32 *)(state + 0x20) = lbl_803E5BC4;
    *(f32 *)(state + 0x24) = lbl_803E5C50;
    *(s8 *)(state + 0x65) = -1;
    fv = lbl_803E5B98;
    *(f32 *)(state + 0x464) = fv;
    *(f32 *)(state + 0x468) = fv;
    *(s16 *)(state + 0x440) = 0x436;
    switch (*(s16 *)(obj + 0x46)) {
    case 0x72:
    default:
        state[0x434] = 1;
        *(f32 *)(state + 0x46c) = lbl_803E5C50;
        *(s16 *)(state + 0x440) = 282;
        break;
    case 0x16c:
        state[0x434] = 1;
        state[0x435] = 0;
        *(f32 *)(state + 0x1c) = lbl_803E5B14;
        *(f32 *)(state + 0x18) = lbl_803E5C54;
        *(s8 *)(state + 0x65) = 1;
        *(f32 *)(state + 0x46c) = lbl_803E5AF0;
        break;
    case 0x16f:
        state[0x434] = 1;
        state[0x58] = 1;
        state[0x435] = 1;
        *(s8 *)(state + 0x65) = 2;
        *(f32 *)(state + 0x46c) = lbl_803E5AF0;
        break;
    case 0x38c:
        state[0x434] = 0;
        *(f32 *)(state + 0x46c) = lbl_803DC0C4;
        *(s16 *)(state + 0x440) = 282;
        break;
    case 0x38d:
        state[0x434] = 0;
        state[0x435] = 0;
        *(f32 *)(state + 0x1c) = lbl_803E5B14;
        *(f32 *)(state + 0x18) = lbl_803E5C54;
        *(f32 *)(state + 0x46c) = lbl_803E5C58 * lbl_803DC0C0;
        break;
    case 0x38e:
        state[0x434] = 0;
        state[0x435] = 1;
        *(f32 *)(state + 0x1c) = lbl_803E5B48;
        *(f32 *)(state + 0x18) = lbl_803E5C5C;
        *(f32 *)(state + 0x46c) = lbl_803E5C60 * lbl_803DC0C0;
        break;
    case 0x4d4:
        state[0x434] = 0;
        state[0x435] = 2;
        *(f32 *)(state + 0x1c) = lbl_803E5B48;
        *(f32 *)(state + 0x18) = lbl_803E5C5C;
        *(f32 *)(state + 0x46c) = lbl_803DC0C0;
        break;
    }
    fv = *(f32 *)(state + 0x464);
    *(f32 *)(state + 0x47c) = fv;
    *(f32 *)(state + 0x470) = fv;
    fv = *(f32 *)(state + 0x468);
    *(f32 *)(state + 0x480) = fv;
    *(f32 *)(state + 0x474) = fv;
    fv = *(f32 *)(state + 0x46c);
    *(f32 *)(state + 0x484) = fv;
    *(f32 *)(state + 0x478) = fv;
    *(char **)(state + 0x60) = base + state[0x434] * 6 + 0xa4;
    if (state[0x434] == 0) {
        if (!((SnowBikeFlags *)(state + 0x428))->b02) {
            ((SnowBikeFlags *)(state + 0x428))->b20 = 1;
            *(f32 *)(state + 0x4c4) = lbl_803E5AE8;
        }
        *(f32 *)(state + 0x538) = lbl_803E5C64;
    } else {
        *(f32 *)(state + 0x538) = lbl_803E5B74;
    }
    path = state + 0x178;
    path[0x25b] = 1;
    (**(void (**)(u8 *, int, int, int))(*gPathControlInterface + 0x4))(path, 0, 0x48607, 1);
    (**(void (**)(u8 *, int, char *, char *, u32 *))(*gPathControlInterface + 0xc))(path, 4, base, base + 0x30, &pathParam);
    if (((SnowBikeFlags *)(state + 0x428))->b02 && *(s8 *)(state + 0x65) != -1) {
        curves_setLocalPointCollisionEx(path, 1, (u8 *)(base + 0x40), &lbl_803DC0B8, 8, *(s8 *)(state + 0x65));
    } else {
        (**(void (**)(u8 *, int, char *, f32 *, int))(*gPathControlInterface + 0x8))(path, 1, base + 0x40, &lbl_803DC0B8, 8);
    }
    path[0x264] = lbl_803E5C68 + lbl_803DC0B8;
    (**(void (**)(int, u8 *))(*gPathControlInterface + 0x20))(obj, path);
}


extern void Obj_SetModelSlotIndex(int obj, int slot);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int drshackle_updateAttachedPosition(int obj, u8 *state);
extern void fn_801EBD60(int obj, u8 *state);
extern void fn_801EC7A0(int obj, u8 *state);
extern void fn_801EA240(int obj, u8 *state, f32 speed, int val, u8 *p, int n);

typedef struct {
    s16 rot[3];
    f32 quad[4];
} SBRotQuad;
extern void fn_8002B8F0(int obj);
extern int Rcp_GetMotionBlurEnabled(void);
extern void setMotionBlur(int a, f32 b);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern void PSVECAdd(f32 *a, f32 *b, f32 *dst);
extern void mtxRotateByVec3s(f32 *mtx, s16 *rot);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern f32 powfBitEstimate(f32 x, f32 y);
extern void setAButtonIcon(int icon);
extern void setBButtonIcon(int icon);
extern char padGetStickX(int pad);
extern char padGetStickY(int pad);
extern u32 getButtonsHeld(int pad);
extern u32 getButtonsJustPressed(int pad);
extern u32 getButtonsJustPressedIfNotBusy(int pad);
extern int getAngle(f32 dx, f32 dz);
extern f32 timeDelta;
extern f32 lbl_803E5B6C;
extern f32 lbl_803E5B70;
extern f32 lbl_803E5BA0;
extern f32 lbl_803E5C18;

void SnowBike_update(int obj)
{
    u8 *state = *(u8 **)(obj + 0xb8);
    f32 mtx1[16];
    f32 mtx2[16];
    SBRotQuad rq1;
    SBRotQuad rq2;
    f32 vec1[3];
    f32 vec2[3];
    f32 dummy1;
    f32 dummy2;
    s8 mode;
    int t;
    f32 fz;
    f32 p;
    f32 v;
    f32 c;

    if (*(s8 *)(obj + 0xac) == -1) {
        if (GameBit_Get(0x1fa) != 0) {
            state[0x420] = 0;
        }
        if (GameBit_Get(0x1fb) != 0) {
            Obj_SetModelSlotIndex(obj, 0x13);
        }
    }
    *(u8 *)(obj + 0xaf) |= 8;
    *(s16 *)(obj + 2) = *(s16 *)(state + 0x41c);
    *(s16 *)(obj + 4) = *(s16 *)(state + 0x41e);
    if (((SnowBikeFlags *)(state + 0x428))->b04 || GameBit_Get(*(s16 *)(state + 0x44a)) != 0) {
        ((SnowBikeFlags *)(state + 0x428))->b04 = 1;
        return;
    }
    mode = *(s8 *)(state + 0x421);
    if (mode != 1) {
        if (mode < 1) {
            if (mode >= 0) {
                *(u8 *)(obj + 0xaf) &= ~8;
                if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                    state[0x420] = 1;
                } else {
                    state[0x420] = 0;
                }
                Sfx_StopObjectChannel(obj, 0x57);
            }
        } else if (mode < 3) {
            fn_801EAE4C(obj, state);
            if (((SnowBikeFlags *)(state + 0x428))->b02) {
                if (drshackle_updateAttachedPosition(obj, state) != 0) {
                    fn_801EBD60(obj, state);
                    fn_801EC7A0(obj, state);
                    if (*(f32 *)(state + 0x3e4) != lbl_803E5AE8) {
                        PSVECScale((f32 *)(state + 0x464), (f32 *)(state + 0x47c), *(f32 *)(state + 0x3e0));
                        PSVECScale((f32 *)(state + 0x494), (f32 *)(state + 0x494), *(f32 *)(state + 0x3e0));
                        *(f32 *)(state + 0x3e4) -= timeDelta;
                        if (*(f32 *)(state + 0x3e4) <= lbl_803E5AE8) {
                            if (Rcp_GetMotionBlurEnabled() != 0) {
                                setMotionBlur(0, lbl_803E5AE8);
                            }
                            *(f32 *)(state + 0x3e4) = lbl_803E5AE8;
                        }
                    } else {
                        *(f32 *)(state + 0x47c) = *(f32 *)(state + 0x464);
                        *(f32 *)(state + 0x480) = *(f32 *)(state + 0x468);
                        *(f32 *)(state + 0x484) = *(f32 *)(state + 0x46c);
                    }
                    fz = lbl_803E5AE8;
                    rq1.quad[1] = fz;
                    rq1.quad[2] = fz;
                    rq1.quad[3] = fz;
                    rq1.quad[0] = lbl_803E5AEC;
                    rq1.rot[0] = -*(s16 *)(state + 0x40e);
                    rq1.rot[1] = -*(s16 *)(obj + 2);
                    rq1.rot[2] = -*(s16 *)(obj + 4);
                    mtxRotateByVec3s(mtx1, rq1.rot);
                    Matrix_TransformPoint(mtx1, lbl_803E5AE8, *(f32 *)(state + 0x4b0) * *(f32 *)(state + 0x544), lbl_803E5AE8, &vec1[0], &dummy1, &vec1[2]);
                    vec1[0] = vec1[0] * *(f32 *)(state + 0x540);
                    vec1[1] = lbl_803E5AE8;
                    PSVECScale(vec1, vec1, timeDelta);
                    PSVECAdd((f32 *)(state + 0x494), vec1, (f32 *)(state + 0x494));
                    *(f32 *)(state + 0x498) = *(f32 *)(state + 0x4b0) * timeDelta + *(f32 *)(state + 0x498);
                    p = powfBitEstimate(*(f32 *)(state + 0x548), timeDelta);
                    *(f32 *)(state + 0x494) *= p;
                    p = powfBitEstimate(*(f32 *)(state + 0x54c), timeDelta);
                    *(f32 *)(state + 0x49c) *= p;
                    fn_801EC1AC(obj, (int)state);
                    Matrix_TransformPoint((f32 *)(state + 0xec), *(f32 *)(state + 0x494), *(f32 *)(state + 0x498), *(f32 *)(state + 0x49c), (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
                    fn_8002B8F0(obj);
                }
            } else {
                setAButtonIcon(0x10);
                setBButtonIcon(0x11);
                *(f32 *)(state + 0x45c) = (f32)padGetStickX(0);
                *(s8 *)(state + 0x460) = (f32)padGetStickY(0);
                *(u32 *)(state + 0x458) = getButtonsHeld(0);
                *(u32 *)(state + 0x450) = getButtonsJustPressed(0);
                *(u32 *)(state + 0x454) = getButtonsJustPressedIfNotBusy(0);
                *(s16 *)(state + 0x44c) = (f32)(u16)getAngle(*(f32 *)(state + 0x45c), (f32)-(int)*(s8 *)(state + 0x460)) / lbl_803E5C18;
                *(f32 *)(state + 0x45c) = *(f32 *)(state + 0x45c) / lbl_803E5B6C;
                v = *(f32 *)(state + 0x45c);
                if (v < lbl_803E5B70) {
                    c = lbl_803E5B70;
                } else if (v > lbl_803E5AEC) {
                    c = lbl_803E5AEC;
                } else {
                    c = v;
                }
                *(f32 *)(state + 0x45c) = c;
                fn_801EBD60(obj, state);
                fn_801EC7A0(obj, state);
                if (*(f32 *)(state + 0x3e4) != lbl_803E5AE8) {
                    PSVECScale((f32 *)(state + 0x464), (f32 *)(state + 0x47c), *(f32 *)(state + 0x3e0));
                    PSVECScale((f32 *)(state + 0x494), (f32 *)(state + 0x494), *(f32 *)(state + 0x3e0));
                    *(f32 *)(state + 0x3e4) -= timeDelta;
                    if (*(f32 *)(state + 0x3e4) <= lbl_803E5AE8) {
                        if (Rcp_GetMotionBlurEnabled() != 0) {
                            setMotionBlur(0, lbl_803E5AE8);
                        }
                        *(f32 *)(state + 0x3e4) = lbl_803E5AE8;
                    }
                } else {
                    *(f32 *)(state + 0x47c) = *(f32 *)(state + 0x464);
                    *(f32 *)(state + 0x480) = *(f32 *)(state + 0x468);
                    *(f32 *)(state + 0x484) = *(f32 *)(state + 0x46c);
                }
                fz = lbl_803E5AE8;
                rq2.quad[1] = fz;
                rq2.quad[2] = fz;
                rq2.quad[3] = fz;
                rq2.quad[0] = lbl_803E5AEC;
                rq2.rot[0] = -*(s16 *)(state + 0x40e);
                rq2.rot[1] = -*(s16 *)(obj + 2);
                rq2.rot[2] = -*(s16 *)(obj + 4);
                mtxRotateByVec3s(mtx2, rq2.rot);
                Matrix_TransformPoint(mtx2, lbl_803E5AE8, *(f32 *)(state + 0x4b0) * *(f32 *)(state + 0x544), lbl_803E5AE8, &vec2[0], &dummy2, &vec2[2]);
                vec2[0] = vec2[0] * *(f32 *)(state + 0x540);
                vec2[1] = lbl_803E5AE8;
                PSVECScale(vec2, vec2, timeDelta);
                PSVECAdd((f32 *)(state + 0x494), vec2, (f32 *)(state + 0x494));
                *(f32 *)(state + 0x498) = *(f32 *)(state + 0x4b0) * timeDelta + *(f32 *)(state + 0x498);
                p = powfBitEstimate(*(f32 *)(state + 0x548), timeDelta);
                *(f32 *)(state + 0x494) *= p;
                p = powfBitEstimate(*(f32 *)(state + 0x54c), timeDelta);
                *(f32 *)(state + 0x49c) *= p;
                fn_801EC1AC(obj, (int)state);
                Matrix_TransformPoint((f32 *)(state + 0xec), *(f32 *)(state + 0x494), *(f32 *)(state + 0x498), *(f32 *)(state + 0x49c), (f32 *)(obj + 0x24), (f32 *)(obj + 0x28), (f32 *)(obj + 0x2c));
                fn_8002B8F0(obj);
            }
            fn_801EB0D4(obj, state);
            fn_801EA240(obj, state, *(f32 *)(state + 0x49c), (int)(lbl_803E5BA0 * -*(f32 *)(state + 0x430)), state + 0x461, 7);
            fn_801EB634(obj, state);
            *(s16 *)obj = *(s16 *)(state + 0x40e);
        }
    }
}
