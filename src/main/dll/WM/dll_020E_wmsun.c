#include "main/dll/WM/wm_shared.h"

int fn_801F6E8C(int p1, int p2, int actor)
{
    int ret;

    ret = 0;
    *(s16 *)(actor + 0x6e) = -1;
    *(u8 *)(actor + 0x56) = (u8)ret;
    return ret;
}

int wmsun_getExtraSize(void) { return 0x10; }

int wmsun_getObjectTypeId(void) { return 0x0; }

void wmsun_hitDetect(void) {}

void wmsun_release(void) {}

void wmsun_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void wmsun_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)((char *)inner + 8) != NULL) {
        mm_free(*(void **)((char *)inner + 8));
    }
    *(int *)((char *)inner + 8) = 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wmsun_render(int p1, int p2, int p3, int p4, int p5, s8 vis) {
    int *inner = *(int **)(p1 + 0xb8);
    if (vis != 0 && *(u8 *)((char *)inner + 0xd) != 0) {
        doNothing_8005D148(p2, 0x10000);
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E5F24);
        doNothing_8005D14C(p2, 0x10000);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int mmAlloc(int size, int tag, int p3);
extern f32 lbl_803E5F8C;
extern s16 lbl_803DDCA8;
extern s16 lbl_803DDCAA;
extern s16 lbl_803DDCAC;
extern s16 lbl_803DDCAE;
extern s16 lbl_803DDCB0;
#pragma scheduling off
#pragma peephole off
void wmsun_init(int obj, int params)
{
    int state = *(int *)(obj + 0xb8);
    u8 c;
    int c2;
    s16 i;
    int j;
    s16 mode;

    *(void **)(obj + 0xbc) = (void *)fn_801F6E8C;
    c = (*(code *)(*gMapEventInterface + 0x40))((int)*(s8 *)(obj + 0xac));
    if (c == 3 && (u32)GameBit_Get(0x21b) == 0) {
        GameBit_Set(0x21b, 1);
    }
    *(int *)(state + 8) = 0;
    *(u8 *)(state + 0xd) = 1;
    mode = *(s16 *)(obj + 0x46);
    if (mode == 0x262) {
        *(s16 *)obj = (s16)(*(s8 *)(params + 0x18) << 8);
        *(s16 *)(state + 2) = 100;
        if (*(s16 *)(params + 0x1c) >= 1000) {
            *(f32 *)(obj + 8) = (f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C;
        } else {
            *(f32 *)(obj + 8) = lbl_803E5F24;
        }
    } else if (mode == 0x2bd) {
        lbl_803DDCB0 = 800;
        lbl_803DDCAE = 800;
        lbl_803DDCAC = 800;
        lbl_803DDCAA = 800;
        lbl_803DDCA8 = 800;
        *(s16 *)obj = (s16)(*(s8 *)(params + 0x18) << 8);
        if (*(s16 *)(params + 0x1c) >= 0) {
            *(f32 *)(obj + 8) = (f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C;
        } else {
            *(f32 *)(obj + 8) = lbl_803E5F24;
        }
        *(u8 *)(obj + 0xad) = *(u8 *)(params + 0x19);
        c2 = *(s8 *)(obj + 0xad);
        if (c2 == 0) {
            *(s16 *)(state + 2) = randomGetRange(300, 600);
            *(s16 *)(state + 4) = randomGetRange(300, 600);
        } else if (c2 == 1) {
            *(s16 *)(state + 2) = randomGetRange(500, 800);
            *(s16 *)(state + 4) = randomGetRange(500, 800);
        } else if (c2 == 2) {
            *(s16 *)(state + 2) = randomGetRange(700, 1000);
            *(s16 *)(state + 4) = randomGetRange(700, 1000);
        }
        *(u8 *)(obj + 0x36) = 0;
    } else if (mode == 0x2c2) {
        *(int *)(state + 8) = mmAlloc(0xa0, 0xe, 0);
        i = 0x14;
        j = 0x28;
        while (i != 0) {
            j -= 2;
            i--;
            *(s16 *)(*(int *)(state + 8) + j + 0x28) = 0;
            *(s16 *)(*(int *)(state + 8) + j + 0x50) = randomGetRange(10, 0x14);
            *(s16 *)(*(int *)(state + 8) + j + 0x78) = randomGetRange(0x50, 0xff);
        }
        *(u8 *)(obj + 0x36) = 0;
        if (*(s16 *)(params + 0x1c) != 0) {
            *(f32 *)(obj + 8) = lbl_803E5F24 / ((f32)*(s16 *)(params + 0x1c) / lbl_803E5F8C);
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

extern int objFindTexture(int obj, int idx, int p3);
extern void CameraShake_SetAllMagnitudes(f32 mag);
extern void fn_801F6EA4(int obj);
extern f32 lbl_803E5F20;
extern f32 lbl_803E5F78;
extern f32 lbl_803E5F7C;
extern f32 lbl_803E5F80;
extern f32 lbl_803E5F84;
extern f32 lbl_803E5F88;
#pragma scheduling off
#pragma peephole off
void wmsun_update(int obj)
{
    int state = *(int *)(obj + 0xb8);
    s16 thresh;
    s16 mult;
    f32 spd;
    int t;
    s8 c;
    u8 b;
    int v;

    thresh = 0;
    mult = 1;
    spd = lbl_803E5F20;
    if (*(s16 *)(obj + 0x46) == 0x262) {
        if (GameBit_Get(0x38f) != 0) {
            Obj_FreeObject(obj);
        } else {
            t = objFindTexture(obj, 1, 0);
            if ((u32)t != 0) {
                *(s16 *)(t + 10) -= 0x10;
                if (*(s16 *)(t + 10) < -0x3e0) {
                    *(s16 *)(t + 10) = 0;
                }
            }
            if (GameBit_Get(0x21b) != 0) {
                thresh = 100;
            }
            if (GameBit_Get(0x21c) != 0) {
                thresh = 200;
            }
            if (GameBit_Get(0x21d) != 0) {
                thresh = 400;
            }
            if (GameBit_Get(0x21f) != 0) {
                thresh = 800;
            }
            if (GameBit_Get(0x221) != 0) {
                thresh = 0x640;
            }
            if (GameBit_Get(0x222) != 0) {
                thresh = 0x1900;
                mult = 3;
                spd = lbl_803E5F78;
            }
            if (*(s16 *)(state + 2) < thresh) {
                *(s16 *)(state + 2) = *(s16 *)(state + 2) + framesThisStep * mult;
                *(f32 *)(obj + 8) = -(spd * timeDelta - *(f32 *)(obj + 8));
                *(f32 *)(obj + 0x10) = lbl_803E5F7C * (spd * timeDelta) + *(f32 *)(obj + 0x10);
            } else if (GameBit_Get(0x222) != 0 && GameBit_Get(0x38d) == 0) {
                GameBit_Set(0x38d, 1);
                GameBit_Set(0x370, 0);
                *(u8 *)(state + 0xd) = 0;
            }
            if (GameBit_Get(0x38d) == 0 && *(s16 *)(state + 2) > 0x960 && (int)randomGetRange(0, 100) == 0) {
                CameraShake_SetAllMagnitudes(lbl_803E5F80 * ((f32)(*(s16 *)(state + 2) - 0x960) / lbl_803E5F84));
                GameBit_Set(0x370, 1);
            }
            *(s16 *)obj += *(s16 *)(state + 2);
            if (*(u8 *)(state + 0xd) == 0) {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (*(s16 *)(obj + 0x46) == 0x2c2) {
        if (GameBit_Get(0x38f) != 0) {
            b = *(u8 *)(obj + 0x36);
            if (b < 0xfa) {
                v = (s16)(b + framesThisStep);
            }
            if (v > 0xfa) {
                v = 0xfa;
            }
            *(u8 *)(obj + 0x36) = v;
            t = objFindTexture(obj, 0, 0);
            if ((u32)t != 0) {
                *(s16 *)(t + 8) = *(s16 *)(t + 8) - framesThisStep * 8;
                if (*(s16 *)(t + 8) < -0x3e0) {
                    *(s16 *)(t + 8) = 0;
                }
            }
        }
        return;
    }
    if (GameBit_Get(0x38f) != 0) {
        c = *(s8 *)(obj + 0xad);
        if (c == 0 && (b = *(u8 *)(obj + 0x36)) != 0xff) {
            if (b < 0xff) {
                v = (s16)(b + framesThisStep);
            }
            if (v > 0xff) {
                v = 0xff;
            }
            *(u8 *)(obj + 0x36) = v;
        } else if (c == 1 && (b = *(u8 *)(obj + 0x36)) != 0x55) {
            if (b < 0x55) {
                v = (s16)(b + framesThisStep);
            }
            if (v > 0x55) {
                v = 0x55;
            }
            *(u8 *)(obj + 0x36) = v;
        } else if (c == 2 && (b = *(u8 *)(obj + 0x36)) != 0x19) {
            if (b < 0x19) {
                v = (s16)(b + framesThisStep);
            }
            if (v > 0x19) {
                v = 0x19;
            }
            *(u8 *)(obj + 0x36) = v;
        }
        if (*(s8 *)(obj + 0xad) == 0) {
            if ((int)randomGetRange(0, 0x96) == 0) {
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                Sfx_PlayFromObject(obj, 0x81);
            }
            fn_801F6EA4(obj);
        }
    } else {
        *(s16 *)(obj + 4) += *(s16 *)(state + 4);
        *(s16 *)obj += *(s16 *)(state + 2);
        if (GameBit_Get(0x38d) != 0 && *(s8 *)(obj + 0xad) == 0) {
            if (lbl_803DDCAA == 0) {
                if (lbl_803DDCA8 > 600 && (int)randomGetRange(0, 10) == 0) {
                    CameraShake_SetAllMagnitudes(lbl_803E5F88);
                }
                if (lbl_803DDCA8 > 0) {
                    lbl_803DDCA8 = lbl_803DDCA8 - framesThisStep;
                    if (lbl_803DDCA8 < 1) {
                        lbl_803DDCA8 = 0;
                        GameBit_Set(0x38d, 0);
                        GameBit_Set(0x38f, 1);
                    }
                }
            }
            if (lbl_803DDCB0 == 0) {
                if (lbl_803DDCAE > 0) {
                    lbl_803DDCAE = lbl_803DDCAE - framesThisStep;
                    if (lbl_803DDCAE < 0) {
                        lbl_803DDCAE = 0;
                    }
                }
            } else {
                if (lbl_803DDCB0 > 0) {
                    lbl_803DDCB0 = lbl_803DDCB0 - framesThisStep;
                    if (lbl_803DDCB0 < 1) {
                        lbl_803DDCB0 = 0;
                        getEnvfxAct(obj, obj, 0x30, 0);
                        getEnvfxAct(obj, obj, 0x34, 0);
                    }
                }
                if ((int)randomGetRange(0, 8) == 0) {
                    CameraShake_SetAllMagnitudes(lbl_803E5F88);
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

typedef struct { f32 x, y, z; } WmSunVec3;
typedef struct {
    s16 ang[3];
    f32 intensity;
    f32 vx;
    f32 vy;
    f32 vz;
} WmSunGlare;
extern WmSunVec3 lbl_802C24E8;
extern WmSunVec3 lbl_802C24F4;
extern f32 lbl_803DDCA0;
extern f32 lbl_803DDCA4;
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5F28;
extern f32 lbl_803E5F2C;
extern f32 lbl_803E5F30;
extern f32 lbl_803E5F34;
extern f32 lbl_803E5F38;
extern f32 lbl_803E5F3C;
extern f32 lbl_803E5F40;
extern f32 lbl_803E5F44;
extern f32 lbl_803E5F48;
extern f32 lbl_803E5F4C;
extern f32 lbl_803E5F54;
extern f32 lbl_803E5F58;
extern f32 lbl_803E5F60;
extern f32 lbl_803E5F64;
extern f32 lbl_803E5F68;
extern f32 sqrtf(f32 x);
extern f32 fn_80293E80(f32 x);
extern int Camera_GetCurrentViewSlot(void);
extern void mathFn_80021ac8(s16 *ang, WmSunVec3 *vec);
#pragma scheduling off
#pragma peephole off
void fn_801F6EA4(int obj)
{
    WmSunVec3 dir;
    WmSunVec3 sun;
    WmSunGlare g;
    int cam;
    f32 dx, dy, dz, len;
    f32 dot, prod, denom, cosang, zero;
    f32 hx, hy, hz, hlen;
    f32 f;
    f32 cz;

    dir = lbl_802C24E8;
    sun = lbl_802C24F4;
    *(s16 *)obj += 400;
    g.vx = lbl_803E5F20;
    g.vy = lbl_803E5F20;
    g.vz = lbl_803E5F20;
    g.intensity = lbl_803E5F24;
    g.ang[2] = 0;
    g.ang[1] = 0;
    g.ang[0] = *(s16 *)obj;
    cam = Camera_GetCurrentViewSlot();
    if ((void *)cam != NULL) {
        g.ang[0] = 0x8000 - *(s16 *)cam;
        mathFn_80021ac8(g.ang, &sun);
        dx = *(f32 *)(obj + 0xc) - *(f32 *)(cam + 0xc);
        dy = *(f32 *)(obj + 0x10) - *(f32 *)(cam + 0x10);
        dz = *(f32 *)(obj + 0x14) - *(f32 *)(cam + 0x14);
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (lbl_803E5F20 != len) {
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
        }
        dot = dz * sun.z + (dx * sun.x + dy * sun.y);
        prod = (dz * dz + (dx * dx + dy * dy)) * (denom = sun.z * sun.z + (sun.x * sun.x + sun.y * sun.y));
        if (prod != lbl_803E5F20) {
            denom = sqrtf(prod);
        }
        cz = lbl_803E5F20;
        if (denom != cz) {
            cosang = dot / denom;
        } else {
            cosang = cz;
        }
        zero = lbl_803E5F20;
        if (cosang > zero) {
            hx = *(f32 *)(obj + 0xc) - *(f32 *)(cam + 0xc);
            hy = zero;
            hz = *(f32 *)(obj + 0x14) - *(f32 *)(cam + 0x14);
            hlen = sqrtf(hz * hz + (hx * hx + hy));
            if (lbl_803E5F20 != hlen) {
                hx = hx / hlen;
                hy = hy / hlen;
                hz = hz / hlen;
            }
            prod = dir.z * dir.z + (dir.x * dir.x + dir.y * dir.y);
            prod = prod * (hz * hz + (hx * hx + hy * hy));
            if (prod != lbl_803E5F20) {
                sqrtf(prod);
            }
            if (cosang > lbl_803E5F28) {
                g.vx = lbl_803E5F2C * hx;
                g.vy = lbl_803E5F20;
                g.vz = lbl_803E5F2C * hz;
                f = fn_80293E80((lbl_803E5F30 * lbl_803E5F34 * (cosang - lbl_803E5F28)) / lbl_803E5F38) - lbl_803DDCA0;
                if (f > lbl_803E5F3C || f < lbl_803E5F40) {
                    lbl_803DDCA0 = lbl_803DDCA0 + f / timeDelta;
                }
                g.intensity = lbl_803DDCA0;
                if (lbl_803DDCA0 > lbl_803E5F44) {
                    if (lbl_803DDCA4 < lbl_803E5F4C) {
                        lbl_803DDCA4 = lbl_803DDCA4 + (lbl_803DDCA0 - lbl_803E5F44) / lbl_803E5F48;
                    }
                    g.intensity = g.intensity - lbl_803DDCA4;
                    if (g.intensity < lbl_803E5F44) {
                        g.intensity = lbl_803E5F44;
                    }
                } else {
                    lbl_803DDCA4 = lbl_803DDCA4 - (lbl_803DDCA0 - lbl_803E5F44) / lbl_803E5F2C;
                }
                randomGetRange(0, 0x1e);
                if (lbl_803E5F58 < lbl_803DDCA0) {
                    lbl_803DDCA0 = lbl_803DDCA0 - lbl_803E5F54;
                }
            } else {
                f = lbl_803E5F20 - lbl_803DDCA0;
                if (f <= lbl_803E5F60) {
                    if (f < lbl_803E5F64) {
                        lbl_803DDCA0 = oneOverTimeDelta * f + lbl_803DDCA0;
                    }
                } else {
                    lbl_803DDCA0 = oneOverTimeDelta * f + lbl_803DDCA0;
                }
                if (lbl_803E5F20 < lbl_803DDCA4) {
                    lbl_803DDCA4 = -(lbl_803E5F68 * timeDelta - lbl_803DDCA4);
                    if (lbl_803DDCA4 < lbl_803E5F20) {
                        lbl_803DDCA4 = lbl_803E5F20;
                    }
                }
            }
        } else {
            if (zero < lbl_803DDCA4) {
                lbl_803DDCA4 = -(lbl_803E5F68 * timeDelta - lbl_803DDCA4);
                if (lbl_803DDCA4 < zero) {
                    lbl_803DDCA4 = lbl_803E5F20;
                }
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
