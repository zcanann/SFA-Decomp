#include "main/dll/DR/dll_80211C24_shared.h"

void ktrexfloorswitch_free(void) {}

int ktrexfloorswitch_getExtraSize(void) { return 0x14; }

int ktrexfloorswitch_getObjectTypeId(void) { return 0x0; }

void ktrexfloorswitch_hitDetect(void) {}

void ktrexfloorswitch_initialise(void) {}

void ktrexfloorswitch_release(void) {}

#pragma scheduling off
#pragma peephole off
void ktrexfloorswitch_render(void *obj, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, char visible) {
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, (double)lbl_803E6858);
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexfloorswitch_init(int obj, char *arg) {
    char *p = *(char **)((char *)obj + 0xb8);
    int q;
    int r;
    *(s16 *)obj = (s16)(((u8 *)arg)[0x18] << 8);
    *(f32 *)(p + 0x8) = (f32)(u32)((u8 *)arg)[0x19];
    *(int *)((char *)obj + 0xf4) = 1;
    *(int *)((char *)obj + 0xf8) = 1;
    q = *(int *)((char *)obj + 0x4c);
    r = (*(int (**)(int, int, int, f32, f32, f32))((char *)*gRomCurveInterface + 0x14))((int)&lbl_803DC2A0, 1, 0, *(f32 *)(q + 0x8), *(f32 *)(q + 0xc), *(f32 *)(q + 0x10));
    if (r != -1) {
        r = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(r);
        if (r != 0) {
            *(f32 *)((char *)obj + 0xc) = *(f32 *)(r + 0x8);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)(r + 0x10);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexfloorswitch_spawnEnergyArc(int obj, f32 scale, int angle) {
    char *runtime = *(char **)((char *)obj + 0xb8);
    f32 pos[3];
    f32 dir[3];
    if (*(void **)(runtime + 0x10) != 0) {
        mm_free(*(void **)(runtime + 0x10));
        *(void **)(runtime + 0x10) = 0;
    }
    pos[0] = *(f32 *)((char *)obj + 0xc);
    pos[1] = *(f32 *)((char *)obj + 0x10);
    pos[2] = *(f32 *)((char *)obj + 0x14);
    dir[0] = lbl_803E6898;
    dir[1] = -((f32)angle * *(f32 *)(runtime + 0xc) * lbl_803E689C);
    dir[2] = scale;
    mathFn_80021ac8(obj, dir);
    dir[0] += *(f32 *)((char *)obj + 0xc);
    dir[1] += *(f32 *)((char *)obj + 0x10);
    dir[2] += *(f32 *)((char *)obj + 0x14);
    *(f32 *)(runtime + 8) = (f32)(int)randomGetRange(10, angle);
    *(void **)(runtime + 0x10) = fn_8008FB20(pos, dir, lbl_803E68A0, lbl_803E68A4, (u16)angle, 96, 0);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ktrexfloorswitch_update(int obj) {
    int *sub = *(int **)((char *)obj + 0x4c);
    int *state = *(int **)((char *)obj + 0xb8);
    int *tex;
    int *player;
    int anim;
    int level;
    int scroll;
    f32 vecA[3];
    f32 vecB[3];
    f32 mtx[12];
    f32 height;
    f32 xLo, xHi, zLo, zHi, cx, cz, sumX, sumZ;
    vecA[0] = lbl_802C2560[0];
    vecA[1] = lbl_802C2560[1];
    vecA[2] = lbl_802C2560[2];
    vecB[0] = lbl_802C256C[0];
    vecB[1] = lbl_802C256C[1];
    vecB[2] = lbl_802C256C[2];
    *(int *)((char *)obj + 0xf8) = *(int *)((char *)obj + 0xf4);
    *(int *)((char *)obj + 0xf4) = GameBit_Get(*(s16 *)((char *)sub + 0x1c));
    tex = objFindTexture(obj, 0, 0);
    anim = 0;
    if (*(int *)((char *)obj + 0xf4) <= 1) {
        *tex = 0;
        if (*(int *)((char *)obj + 0xf4) == 0 && *(int *)((char *)obj + 0xf8) != 0) {
            *(u8 *)((char *)state + 0x10) |= 0x4;
        }
        if (*(int *)((char *)obj + 0xf4) != 0 && *(int *)((char *)obj + 0xf8) == 0) {
            int cp;
            *(u8 *)((char *)state + 0x10) |= 0x2;
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)sub + 0xc) - (f32)(u32)*(u8 *)((char *)sub + 0x1f);
            cp = (*(int (**)(int, int, int, f32, f32, f32))((char *)*gRomCurveInterface + 0x14))(
                (int)&lbl_803DC2A0, 1, GameBit_Get(0x572) >> 1, *(f32 *)(*(int *)((char *)obj + 0x4c) + 8),
                *(f32 *)(*(int *)((char *)obj + 0x4c) + 0xc), *(f32 *)(*(int *)((char *)obj + 0x4c) + 0x10));
            if (cp != -1) {
                cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(cp);
                if (cp != 0) {
                    *(f32 *)((char *)obj + 0xc) = *(f32 *)(cp + 0x8);
                    *(f32 *)((char *)obj + 0x14) = *(f32 *)(cp + 0x10);
                }
            }
        }
        if ((*(u8 *)((char *)state + 0x10) & 0x6) == 0) {
            return;
        }
    } else {
        if (*(int *)((char *)obj + 0xf8) == 0) {
            *tex = 0x100;
            *(u8 *)((char *)state + 0x10) &= ~1;
        } else {
            int cp;
            *(u8 *)((char *)state + 0x10) |= 0x2;
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)sub + 0xc) - (f32)(u32)*(u8 *)((char *)sub + 0x1f);
            cp = (*(int (**)(int, int, int, f32, f32, f32))((char *)*gRomCurveInterface + 0x14))(
                (int)&lbl_803DC2A0, 1, GameBit_Get(0x572) >> 1, *(f32 *)(*(int *)((char *)obj + 0x4c) + 8),
                *(f32 *)(*(int *)((char *)obj + 0x4c) + 0xc), *(f32 *)(*(int *)((char *)obj + 0x4c) + 0x10));
            if (cp != -1) {
                cp = (*(int (**)(int))((char *)*gRomCurveInterface + 0x1c))(cp);
                if (cp != 0) {
                    *(f32 *)((char *)obj + 0xc) = *(f32 *)(cp + 0x8);
                    *(f32 *)((char *)obj + 0x14) = *(f32 *)(cp + 0x10);
                }
            }
        }
    }
    *(u8 *)((char *)state + 0x4) -= 1;
    if ((s8)*(u8 *)((char *)state + 0x4) < 0) {
        *(u8 *)((char *)state + 0x4) = 0;
    }
    if ((s8)*(s8 *)(*(int *)((char *)obj + 0x58) + 0x10f) > 0 && *(int *)((char *)obj + 0xf4) == 2) {
        player = (int *)Obj_GetPlayerObject();
        if (player != 0) {
            PSMTXRotRad(mtx, 0x79, (f32)(lbl_803E6860 * (f64)*(s16 *)obj / lbl_803E6868));
            PSMTXMultVecSR(mtx, vecA, vecA);
            PSMTXMultVecSR(mtx, vecB, vecB);
            cx = *(f32 *)((char *)obj + 0xc);
            sumX = vecB[0] + (cx + vecA[0]);
            if (sumX < cx) {
                xHi = cx;
                xLo = sumX;
            } else {
                xHi = sumX;
                xLo = cx;
            }
            cz = *(f32 *)((char *)obj + 0x14);
            sumZ = vecB[2] + (cz + vecA[2]);
            if (sumZ < cz) {
                zHi = cz;
                zLo = sumZ;
            } else {
                zHi = sumZ;
                zLo = cz;
            }
            xLo += lbl_803E6870;
            xHi -= lbl_803E6870;
            zLo += lbl_803E6870;
            zHi -= lbl_803E6870;
            if (*(f32 *)((char *)player + 0xc) >= xLo && *(f32 *)((char *)player + 0xc) <= xHi &&
                *(f32 *)((char *)player + 0x14) >= zLo && *(f32 *)((char *)player + 0x14) <= zHi) {
                *(u8 *)((char *)state + 0x4) = 5;
            }
        }
    }
    if ((*(u8 *)((char *)state + 0x10) & 0x4) != 0) {
        height = *(f32 *)((char *)sub + 0xc) - (f32)(u32)*(u8 *)((char *)sub + 0x1f);
        if (*(f32 *)((char *)obj + 0x10) > height) {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x10) - lbl_803E6874 * timeDelta;
            if (*(f32 *)((char *)obj + 0x10) <= height) {
                *(f32 *)((char *)obj + 0x10) = height;
                *(u8 *)((char *)state + 0x10) &= ~0x4;
            } else {
                anim = 1;
                (*(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x488, 0, 2, -1, 0);
            }
        }
    } else if ((*(u8 *)((char *)state + 0x10) & 0x2) != 0) {
        if (*(f32 *)((char *)obj + 0x10) < *(f32 *)((char *)sub + 0xc)) {
            *(f32 *)((char *)obj + 0x10) = lbl_803E6874 * timeDelta + *(f32 *)((char *)obj + 0x10);
            if (*(f32 *)((char *)obj + 0x10) >= *(f32 *)((char *)sub + 0xc)) {
                *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)sub + 0xc);
                *(u8 *)((char *)state + 0x10) &= ~0x2;
            } else {
                anim = 1;
                (*(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x488, 0, 2, -1, 0);
            }
        }
    } else if ((s8)*(u8 *)((char *)state + 0x4) != 0 && (*(u8 *)((char *)state + 0x10) & 1) == 0) {
        height = *(f32 *)((char *)sub + 0xc) - (f32)(u32)*(u8 *)((char *)sub + 0x1e);
        if (*(f32 *)((char *)obj + 0x10) > height) {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)obj + 0x10) - lbl_803E6878 * timeDelta;
            if (*(f32 *)((char *)obj + 0x10) < height) {
                *(f32 *)((char *)obj + 0x10) = height;
            } else {
                anim = 1;
            }
        }
        if (*(f32 *)((char *)state + 0x8) < lbl_803E687C) {
            *(f32 *)((char *)state + 0x8) = (f32)(u32)*(u8 *)((char *)sub + 0x19);
            level = GameBit_Get(*(s16 *)((char *)sub + 0x1a)) & 0xff;
            if (level < 0xf) {
                level += 1;
                GameBit_Set(*(s16 *)((char *)sub + 0x1a), level);
                if (level == 0xf) {
                    *(u8 *)((char *)state + 0x10) |= 0x8;
                }
            } else {
                *(u8 *)((char *)state + 0x10) &= ~0x8;
                *(u8 *)((char *)state + 0x10) |= 1;
                GameBit_Set(*(s16 *)((char *)sub + 0x1a), 0);
                if (GameBit_Get(0x55a) != 0) {
                    GameBit_Set(0x55a, 0);
                    GameBit_Set(0x55b, 1);
                } else {
                    GameBit_Set(0x55a, 1);
                    GameBit_Set(0x55b, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
        }
        *(f32 *)((char *)state + 0x8) -= timeDelta;
    } else {
        *(f32 *)((char *)obj + 0x10) = lbl_803E6878 * timeDelta + *(f32 *)((char *)obj + 0x10);
        if (*(f32 *)((char *)obj + 0x10) > *(f32 *)((char *)sub + 0xc)) {
            *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)sub + 0xc);
        } else {
            anim = 1;
        }
        if ((*(u8 *)((char *)state + 0x10) & 0x8) != 0) {
            if (*(f32 *)((char *)state + 0x8) < lbl_803E687C) {
                *(u8 *)((char *)state + 0x10) &= ~0x8;
                *(u8 *)((char *)state + 0x10) |= 1;
                GameBit_Set(*(s16 *)((char *)sub + 0x1a), 0);
                if (GameBit_Get(0x55a) != 0) {
                    GameBit_Set(0x55a, 0);
                    GameBit_Set(0x55b, 1);
                } else {
                    GameBit_Set(0x55a, 1);
                    GameBit_Set(0x55b, 0);
                }
                ktrexlevel_updatePathGameBits();
            }
            *(f32 *)((char *)state + 0x8) -= timeDelta;
        }
    }
    if ((*(u8 *)((char *)state + 0x10) & 1) == 0 && (s8)*(u8 *)((char *)state + 0x5) != (s8)*(u8 *)((char *)state + 0x4)) {
        GameBit_Get(*(s16 *)((char *)sub + 0x1a));
        GameBit_Set(*(s16 *)((char *)sub + 0x1a), 0);
    }
    if ((s8)anim != 0 && lbl_803DDD60 == 0) {
        Sfx_PlayFromObject(obj, 0x85);
    }
    lbl_803DDD60 = (s8)anim;
    if (*(int *)((char *)obj + 0xf4) == 2) {
        if ((s8)*(u8 *)((char *)state + 0x4) != 0) {
            if (lbl_803E687C == *(f32 *)((char *)state + 0xc)) {
                *(f32 *)((char *)state + 0xc) = lbl_803E6880;
            }
            scroll = (int)(timeDelta * *(f32 *)((char *)state + 0xc) + (f32)*tex);
            if (scroll > 0x200) {
                scroll = 0x400 - scroll;
                *(f32 *)((char *)state + 0xc) = -*(f32 *)((char *)state + 0xc);
            } else if (scroll < 0x100) {
                scroll = 0x200 - scroll;
                *(f32 *)((char *)state + 0xc) = -*(f32 *)((char *)state + 0xc);
            }
            *tex = scroll;
        } else {
            scroll = (int)(timeDelta * *(f32 *)((char *)state + 0xc) + (f32)*tex);
            if (scroll > 0x200) {
                scroll = 0x400 - scroll;
                *(f32 *)((char *)state + 0xc) = -*(f32 *)((char *)state + 0xc);
            } else if (scroll < 0x100) {
                scroll = 0x100;
                *(f32 *)((char *)state + 0xc) = lbl_803E687C;
            }
            *tex = scroll;
        }
        if ((*(u8 *)((char *)state + 0x10) & 0x6) == 0) {
            (*(void (**)(int, int, int, int, int, int))((char *)*gPartfxInterface + 0x8))(obj, 0x486, 0, 2, -1, 0);
        }
    } else {
        if (*tex != 0) {
            scroll = (int)(timeDelta * *(f32 *)((char *)state + 0xc) + (f32)*tex);
            if (scroll > 0x200) {
                scroll = 0x400 - scroll;
                *(f32 *)((char *)state + 0xc) = -*(f32 *)((char *)state + 0xc);
            } else if (scroll < 0x100) {
                scroll = 0;
            }
            *tex = scroll;
        }
    }
    *(u8 *)((char *)state + 0x5) = *(u8 *)((char *)state + 0x4);
}
#pragma peephole reset
#pragma scheduling reset
