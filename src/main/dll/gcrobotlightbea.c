#include "ghidra_import.h"
#include "main/dll/gcrobotlightbea.h"


#pragma peephole off
#pragma scheduling off
extern undefined4 GameBit_Set(int eventId, int value);
extern uint FUN_80017730();
extern undefined4 FUN_80017748();
extern u32 randomGetRange(int min, int max);
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern uint FUN_80294d50();
extern uint FUN_80294d58();

extern undefined4 DAT_803ad3f0;
extern undefined4 DAT_803ad3f4;
extern undefined4 DAT_803ad3f8;
extern f64 DOUBLE_803e4600;
extern f32 lbl_803E45C8;
extern f32 lbl_803E45D0;
extern f32 lbl_803E45D4;
extern f32 lbl_803E45D8;
extern f32 lbl_803E45DC;
extern f32 lbl_803E45E0;
extern f32 lbl_803E45E4;
extern f32 lbl_803E45E8;
extern f32 lbl_803E45EC;
extern f32 lbl_803E45F0;
extern f32 lbl_803E45F4;
extern f32 lbl_803E45F8;
extern f32 lbl_803E45FC;

extern u8 Obj_IsLoadingLocked(void);
extern int fn_80296AE8(u8 *obj);
extern int fn_80296AD4(u8 *obj);
extern u8 *Obj_AllocObjectSetup(int size, int typeId);
extern u8 *Obj_SetupObject(u8 *setup, int a, int b, int c, void *d);
extern f32 sqrtf(f32 x);
extern int getAngle(f32 dx, f32 dz);
extern void mathFn_80021ac8(void *in, void *out);

extern f32 lbl_803AC790[];
extern f32 lbl_803E3930;
extern f32 lbl_803E3938;
extern f32 lbl_803E393C;
extern f32 lbl_803E3940;
extern f32 lbl_803E3944;
extern f32 lbl_803E3948;
extern f32 lbl_803E394C;
extern f32 lbl_803E3950;
extern f32 lbl_803E3954;
extern f32 lbl_803E3958;
extern f32 lbl_803E395C;
extern f32 lbl_803E3960;
extern f32 lbl_803E3964;

/*
 * --INFO--
 *
 * Function: fn_801816F8
 * EN v1.0 Address: 0x801816F8
 * EN v1.0 Size: 2820b
 */
int fn_801816F8(u8 *obj, u8 *player, u8 *dataIn) {
    int mode;
    u8 *data;
    f32 *vel;
    u8 slowMo;
    u8 *setup;
    u8 *spawned;
    int bit;
    int max;
    int ang;
    int diff;
    f32 num;
    f32 den;
    f32 ratio;
    f32 sc;
    f32 mag;
    struct {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } spread;

    data = dataIn;
    slowMo = 0;
    bit = *(s16 *)(data + 0x1c);
    if (bit != -1) {
        GameBit_Set(bit, 1);
    }
    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    vel = lbl_803AC790;
    if (vel[1] < lbl_803E393C) {
        slowMo = 1;
    }
    if (data[0x1e] == 7) {
        num = (f32)(int)fn_80296AE8(player);
        den = (f32)(int)fn_80296AD4(player);
        ratio = num / den;
        ratio = ratio * lbl_803E3930;
        if (ratio <= lbl_803E3940) {
            mode = 6;
        } else if (ratio <= lbl_803E3944) {
            if ((int)randomGetRange(0, (s16)(int)(ratio - lbl_803E3940)) < 7) {
                mode = 6;
                max = (s16)(int)(den * lbl_803E393C);
                if (max < 1) {
                    max = 1;
                }
                randomGetRange(1, max);
            } else {
                mode = 1;
                randomGetRange(1, 4);
            }
        } else {
            return 1;
        }
    } else {
        mode = data[0x1e];
    }

    switch ((s16)mode) {
    case 1:
        setup = Obj_AllocObjectSetup(0x24, 0x3d3);
        *(f32 *)(setup + 0x8) = *(f32 *)(obj + 0xc);
        *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
        *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
        *(s16 *)(setup + 0x1a) = 0x190;
        spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(void **)(obj + 0x30));
        if (slowMo) {
            sc = lbl_803E3948;
            *(f32 *)(spawned + 0x24) = sc * lbl_803AC790[0];
            *(f32 *)(spawned + 0x28) = lbl_803E394C * vel[1];
            *(f32 *)(spawned + 0x2c) = sc * vel[2];
        } else {
            *(f32 *)(spawned + 0x24) = *(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc);
            *(f32 *)(spawned + 0x2c) = *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14);
        }
        mag = *(f32 *)(spawned + 0x24) * *(f32 *)(spawned + 0x24);
        mag += *(f32 *)(spawned + 0x2c) * *(f32 *)(spawned + 0x2c);
        if (mag != lbl_803E3938) {
            mag = sqrtf(mag);
            *(f32 *)(spawned + 0x24) = *(f32 *)(spawned + 0x24) / mag;
            *(f32 *)(spawned + 0x2c) = *(f32 *)(spawned + 0x2c) / mag;
        }
        *(f32 *)(spawned + 0x24) =
            *(f32 *)(spawned + 0x24) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x2c) =
            *(f32 *)(spawned + 0x2c) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x28) = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = (s16)randomGetRange(-10000, 10000);
        mathFn_80021ac8(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)getAngle(*(f32 *)(spawned + 0x24), -*(f32 *)(spawned + 0x2c));
        diff = *(s16 *)spawned - ang;
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        *(s16 *)spawned = diff;
        break;
    case 2:
        setup = Obj_AllocObjectSetup(0x24, 0x3d4);
        *(s8 *)(setup + 0x18) = (s8)randomGetRange(-0x7f, 0x7e);
        *(f32 *)(setup + 0x8) = *(f32 *)(obj + 0xc);
        *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
        *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
        *(s16 *)(setup + 0x1a) = 0x190;
        spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(void **)(obj + 0x30));
        if (slowMo) {
            sc = lbl_803E3948;
            *(f32 *)(spawned + 0x24) = sc * lbl_803AC790[0];
            *(f32 *)(spawned + 0x28) = lbl_803E394C * vel[1];
            *(f32 *)(spawned + 0x2c) = sc * vel[2];
        } else {
            *(f32 *)(spawned + 0x24) = *(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc);
            *(f32 *)(spawned + 0x2c) = *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14);
        }
        mag = *(f32 *)(spawned + 0x24) * *(f32 *)(spawned + 0x24);
        mag += *(f32 *)(spawned + 0x2c) * *(f32 *)(spawned + 0x2c);
        if (mag != lbl_803E3938) {
            mag = sqrtf(mag);
            *(f32 *)(spawned + 0x24) = *(f32 *)(spawned + 0x24) / mag;
            *(f32 *)(spawned + 0x2c) = *(f32 *)(spawned + 0x2c) / mag;
        }
        *(f32 *)(spawned + 0x24) =
            *(f32 *)(spawned + 0x24) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x2c) =
            *(f32 *)(spawned + 0x2c) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x28) = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = (s16)randomGetRange(-10000, 10000);
        mathFn_80021ac8(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)getAngle(*(f32 *)(spawned + 0x24), -*(f32 *)(spawned + 0x2c));
        diff = *(s16 *)spawned - ang;
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        *(s16 *)spawned = diff;
        break;
    case 3:
        setup = Obj_AllocObjectSetup(0x24, 0x3d5);
        *(s8 *)(setup + 0x18) = (s8)randomGetRange(-0x7f, 0x7e);
        *(f32 *)(setup + 0x8) = *(f32 *)(obj + 0xc);
        *(f32 *)(setup + 0xc) = *(f32 *)(obj + 0x10);
        *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
        *(s16 *)(setup + 0x1a) = 0x7d0;
        spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(void **)(obj + 0x30));
        if (slowMo) {
            sc = lbl_803E3948;
            *(f32 *)(spawned + 0x24) = sc * lbl_803AC790[0];
            *(f32 *)(spawned + 0x28) = lbl_803E394C * vel[1];
            *(f32 *)(spawned + 0x2c) = sc * vel[2];
        } else {
            *(f32 *)(spawned + 0x24) = *(f32 *)(obj + 0xc) - *(f32 *)(player + 0xc);
            *(f32 *)(spawned + 0x2c) = *(f32 *)(obj + 0x14) - *(f32 *)(player + 0x14);
        }
        mag = *(f32 *)(spawned + 0x24) * *(f32 *)(spawned + 0x24);
        mag += *(f32 *)(spawned + 0x2c) * *(f32 *)(spawned + 0x2c);
        if (mag != lbl_803E3938) {
            mag = sqrtf(mag);
            *(f32 *)(spawned + 0x24) = *(f32 *)(spawned + 0x24) / mag;
            *(f32 *)(spawned + 0x2c) = *(f32 *)(spawned + 0x2c) / mag;
        }
        *(f32 *)(spawned + 0x24) =
            *(f32 *)(spawned + 0x24) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x2c) =
            *(f32 *)(spawned + 0x2c) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x28) = lbl_803E3958;
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = (s16)randomGetRange(-10000, 10000);
        mathFn_80021ac8(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)getAngle(*(f32 *)(spawned + 0x24), -*(f32 *)(spawned + 0x2c));
        diff = *(s16 *)spawned - ang;
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        *(s16 *)spawned = diff;
        break;
    case 5:
    case 6:
        if (data[0x1e] == 5) {
            setup = Obj_AllocObjectSetup(0x30, 0xb);
        } else {
            setup = Obj_AllocObjectSetup(0x30, 0x3cd);
        }
        setup[0x1a] = 0x14;
        *(s16 *)(setup + 0x2c) = -1;
        *(s16 *)(setup + 0x1c) = -1;
        if ((s8)data[9] != 0) {
            *(f32 *)(setup + 0x8) =
                *(f32 *)(obj + 0xc) + (f32)(int)randomGetRange(-0xf, 0xf);
            *(f32 *)(setup + 0xc) = lbl_803E395C + *(f32 *)(obj + 0x10);
            *(f32 *)(setup + 0x10) =
                *(f32 *)(obj + 0x14) + (f32)(int)randomGetRange(-0xf, 0xf);
        } else {
            *(f32 *)(setup + 0x8) = *(f32 *)(obj + 0xc);
            *(f32 *)(setup + 0xc) = lbl_803E3960 + *(f32 *)(obj + 0x10);
            *(f32 *)(setup + 0x10) = *(f32 *)(obj + 0x14);
        }
        *(s16 *)(setup + 0x24) = -1;
        spawned = Obj_SetupObject(setup, 5, *(s8 *)(obj + 0xac), -1, *(void **)(obj + 0x30));
        if (slowMo) {
            sc = lbl_803E3948;
            *(f32 *)(spawned + 0x24) = sc * lbl_803AC790[0];
            *(f32 *)(spawned + 0x28) = lbl_803E394C * vel[1];
            *(f32 *)(spawned + 0x2c) = sc * vel[2];
        }
        mag = *(f32 *)(spawned + 0x24) * *(f32 *)(spawned + 0x24);
        mag += *(f32 *)(spawned + 0x2c) * *(f32 *)(spawned + 0x2c);
        if (mag != lbl_803E3938) {
            mag = sqrtf(mag);
            *(f32 *)(spawned + 0x24) = *(f32 *)(spawned + 0x24) / (mag = lbl_803E3964 * mag);
            *(f32 *)(spawned + 0x2c) = *(f32 *)(spawned + 0x2c) / mag;
        }
        *(f32 *)(spawned + 0x24) =
            *(f32 *)(spawned + 0x24) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x2c) =
            *(f32 *)(spawned + 0x2c) *
            -(lbl_803E3954 * (f32)(int)randomGetRange(0, 0x19) - lbl_803E3950);
        *(f32 *)(spawned + 0x28) = lbl_803E3958;
        (*(code *)(*(int *)*(int *)(spawned + 0x68) + 0x2c))(
            spawned, *(f32 *)(spawned + 0x24), *(f32 *)(spawned + 0x28),
            *(f32 *)(spawned + 0x2c));
        spread.f14 = lbl_803E3938;
        spread.f18 = lbl_803E3938;
        spread.f1c = lbl_803E3938;
        spread.f10 = lbl_803E3950;
        spread.fc = 0;
        spread.fa = 0;
        spread.f8 = (s16)randomGetRange(-10000, 10000);
        mathFn_80021ac8(&spread.f8, spawned + 0x24);
        ang = (u16)(s16)getAngle(*(f32 *)(spawned + 0x24), -*(f32 *)(spawned + 0x2c));
        diff = *(s16 *)spawned - ang;
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        *(s16 *)spawned = diff;
        break;
    }
    return 1;
}

extern int objBboxFn_800640cc(void *from, void *to, f32 radius, int mode, void *hit, void *obj,
                              int p7, int p8, int p9, int p10);
extern void hitDetect_calcSweptSphereBounds(u32 *boundsOut, f32 *startPoints, f32 *endPoints,
                                            f32 *radii, int pointCount);
extern void hitDetectFn_800691c0(u8 *obj, void *bounds, uint mask, int flags);
extern u8 hitDetectFn_80067958(u8 *obj, f32 *startPoints, f32 *endPoints, int pointCount,
                               void *outHits, int flags);
extern f32 lbl_803AC790[];
extern f32 lbl_803E3938;
extern f32 lbl_803E3970;

/*
 * --INFO--
 *
 * Function: fn_801821FC
 * EN v1.0 Address: 0x801821FC
 * EN v1.0 Size: 776b
 */
int fn_801821FC(u8 *obj) {
    typedef struct {
        f32 hitInfo[4][4];
        f32 radii[4];
        s8 axes[12];
        u32 solidFlags[4];
    } HitDetectResults;

    u8 *st;
    s8 *axes;
    f32 *endY;
    f32 *endZ;
    int idx;
    u8 hit;
    f32 fz;
    HitDetectResults hitResults;
    f32 endPoints[12];
    f32 startPoints[12];
    u32 sweptBounds[6];

    st = *(u8 **)(obj + 0x54);
    if (objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E3970, 1, 0, obj, 1, -1, 0xff, 0) != 0) {
        *(s8 *)(st + 0xad) |= 1;
        *(f32 *)(st + 0x10) = *(f32 *)(obj + 0x80);
        *(f32 *)(st + 0x14) = *(f32 *)(obj + 0x84);
        *(f32 *)(st + 0x18) = *(f32 *)(obj + 0x88);
        fz = lbl_803E3938;
        *(f32 *)(obj + 0x24) = fz;
        *(f32 *)(obj + 0x28) = fz;
        *(f32 *)(obj + 0x2c) = fz;
        return 1;
    }

    if ((int)(*(u32 *)(st + 0x48) >> 4) != 0 && (s8)st[0x70] == 0) {
        endPoints[0] = *(f32 *)(obj + 0xc);
        endY = &endPoints[1];
        endPoints[1] = *(f32 *)(obj + 0x10);
        endZ = &endPoints[2];
        endPoints[2] = *(f32 *)(obj + 0x14);
        startPoints[0] = *(f32 *)(obj + 0x80);
        startPoints[1] = *(f32 *)(obj + 0x84);
        startPoints[2] = *(f32 *)(obj + 0x88);
        hitResults.radii[0] = (f32)*(s16 *)(st + 0x5a);
        axes = hitResults.axes;
        hitResults.axes[0] = -1;
        hitResults.axes[4] = 3;
    } else {
        return 0;
    }

    hitDetect_calcSweptSphereBounds(sweptBounds, startPoints, endPoints, hitResults.radii, 1);
    hitDetectFn_800691c0(obj, sweptBounds, *(u16 *)(st + 0xb2), 1);
    hit = hitDetectFn_80067958(obj, startPoints, endPoints, 1, &hitResults, 0);
    if (hit != 0) {
        if (hit & 1) {
            idx = 0;
        } else if (hit & 2) {
            idx = 1;
        } else if (hit & 4) {
            idx = 2;
        } else {
            idx = 3;
        }
        st[0xac] = axes[idx];
        *(f32 *)(st + 0x3c) = endPoints[idx * 3];
        *(f32 *)(st + 0x40) = endY[idx * 3];
        *(f32 *)(st + 0x44) = endZ[idx * 3];
        lbl_803AC790[0] = hitResults.hitInfo[idx][0];
        lbl_803AC790[1] = hitResults.hitInfo[idx][1];
        lbl_803AC790[2] = hitResults.hitInfo[idx][2];
        lbl_803AC790[3] = hitResults.hitInfo[idx][3];
        if (hitResults.solidFlags[idx] != 0) {
            *(s8 *)(st + 0xad) |= 2;
            *(f32 *)(obj + 0xc) = *(f32 *)(st + 0x3c);
            *(f32 *)(obj + 0x10) = *(f32 *)(st + 0x40);
            *(f32 *)(obj + 0x14) = *(f32 *)(st + 0x44);
            *(f32 *)(st + 0x10) = *(f32 *)(obj + 0x80);
            *(f32 *)(st + 0x14) = *(f32 *)(obj + 0x84);
            *(f32 *)(st + 0x18) = *(f32 *)(obj + 0x88);
            fz = lbl_803E3938;
            *(f32 *)(obj + 0x24) = fz;
            *(f32 *)(obj + 0x28) = fz;
            *(f32 *)(obj + 0x2c) = fz;
            return 1;
        } else {
            *(s8 *)(st + 0xad) |= 1;
            *(f32 *)(obj + 0xc) = *(f32 *)(st + 0x3c);
            *(f32 *)(obj + 0x10) = *(f32 *)(st + 0x40);
            *(f32 *)(obj + 0x14) = *(f32 *)(st + 0x44);
            *(f32 *)(st + 0x10) = *(f32 *)(obj + 0x80);
            *(f32 *)(st + 0x14) = *(f32 *)(obj + 0x84);
            *(f32 *)(st + 0x18) = *(f32 *)(obj + 0x88);
            fz = lbl_803E3938;
            *(f32 *)(obj + 0x24) = fz;
            *(f32 *)(obj + 0x28) = fz;
            *(f32 *)(obj + 0x2c) = fz;
            return 1;
        }
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: smallbasket_getExtraSize
 * EN v1.0 Address: 0x80182594
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018291C
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int smallbasket_getExtraSize(void)
{
  return 0x24;
}

extern void smallbasket_init();
extern void smallbasket_update();
extern void smallbasket_render(int param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                              undefined4 param_5, char param_6);
extern undefined4* gModgfxInterface;
extern void* lbl_803DDAC0;
extern void Resource_Release(void* handle);
extern void ObjGroup_RemoveObject(int obj, int flag);

/*
 * --INFO--
 *
 * Function: smallbasket_free
 * EN v1.0 Address: 0x8018259C
 * EN v1.0 Size: 80b
 */
#pragma scheduling off
void smallbasket_free(int param_1)
{
  (*(code *)(*(int *)gModgfxInterface + 0x18))(param_1);
  Resource_Release(lbl_803DDAC0);
  ObjGroup_RemoveObject(param_1, 0x10);
}
#pragma scheduling reset

extern undefined4* gMapEventInterface;
extern f32 lbl_803E3938;
extern f32 lbl_803E3950;
extern f32 lbl_803E3958;
extern f32 lbl_803E3974;
extern void objRenderFn_8003b8f4(void* obj, undefined4 p2, undefined4 p3, undefined4 p4,
                                 undefined4 p5, double scale);
extern void* Obj_GetPlayerObject(void);
extern void mathFn_80021ac8(void* in, void* out);

/*
 * --INFO--
 *
 * Function: objThrowFn_80182504
 * EN v1.0 Address: 0x80182504
 * EN v1.0 Size: 144b
 */
void objThrowFn_80182504(int param_1)
{
  struct LocalArgs {
    short f8;
    short fa;
    short fc;
    short pad_e;
    float f10;
    float f14;
    float f18;
    float f1c;
  } local;
  int extra;
  short* player;
  extra = *(int*)(param_1 + 0xb8);
  player = (short*)Obj_GetPlayerObject();
  *(char*)(extra + 6) = 0;
  *(char*)(extra + 5) = 0;
  *(char*)(extra + 9) = 1;
  *(float*)(param_1 + 0x28) = lbl_803E3958;
  *(float*)(param_1 + 0x2c) = lbl_803E3974;
  local.f14 = lbl_803E3938;
  local.f18 = lbl_803E3938;
  local.f1c = lbl_803E3938;
  local.f10 = lbl_803E3950;
  local.fc = 0;
  local.fa = 0;
  local.f8 = *player;
  mathFn_80021ac8(&local.f8, (void*)(param_1 + 0x24));
}

/*
 * --INFO--
 *
 * Function: smallbasket_render
 * EN v1.0 Address: 0x801825EC
 * EN v1.0 Size: 252b
 */
void smallbasket_render(int param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4,
                        undefined4 param_5, char param_6)
{
  int extra;
  int result;
  short field_a;
  extra = *(int*)(param_1 + 0xb8);
  result = (int)(*(code *)(*(int *)gMapEventInterface + 0x68))(
    *(int*)(*(int*)(param_1 + 0x4c) + 0x14));
  if (result == 0) {
    *(short*)(param_1 + 6) = *(short*)(param_1 + 6) | 0x4000;
  } else {
    field_a = *(short*)(extra + 0xa);
    if ((field_a != 0 && field_a <= 0x32) || *(int*)(extra + 0x14) != 0) {
      *(short*)(param_1 + 6) = *(short*)(param_1 + 6) | 0x4000;
    } else if (*(int*)(param_1 + 0xf8) != 0 && param_6 != -1) {
      *(short*)(param_1 + 6) = *(short*)(param_1 + 6) | 0x4000;
    } else {
      objRenderFn_8003b8f4((void*)param_1, param_2, param_3, param_4, param_5,
                            (double)lbl_803E3950);
    }
  }
}

ObjectDescriptor gSmallBasketObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)smallbasket_init,
    (ObjectDescriptorCallback)smallbasket_update,
    0,
    (ObjectDescriptorCallback)smallbasket_render,
    (ObjectDescriptorCallback)smallbasket_free,
    0,
    smallbasket_getExtraSize,
};
