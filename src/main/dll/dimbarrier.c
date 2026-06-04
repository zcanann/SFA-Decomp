#include "ghidra_import.h"
#include "main/dll/dimbarrier.h"
#include "main/objanim.h"

extern undefined4 FUN_800067e8();
extern void* FUN_80017624();
extern undefined4 FUN_8001771c();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_EnableObject();
extern undefined4 ObjGroup_FindNearestObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_800810ec();
extern undefined4 FUN_801c7390();

extern undefined4 DAT_802c2b38;
extern undefined4 DAT_802c2b3c;
extern undefined4 DAT_802c2b40;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd708;
extern f32 lbl_803DC074;

extern f32 lbl_803E5064;
extern f32 lbl_803E5068;
extern f32 lbl_803E506C;
extern f32 lbl_803E5070;
extern f32 lbl_803E5074;
extern f32 lbl_803E5078;
extern f32 lbl_803E507C;
extern f32 lbl_803E5080;
extern f32 lbl_803E5084;
extern f32 lbl_803E5088;
extern f64 lbl_803E5090;
extern f64 lbl_803E5098;
extern undefined4 lbl_803DDBC8;
extern int randomGetRange(int min, int max);

/*
 * --INFO--
 *
 * Function: ecsh_cup_update
 * EN v1.0 Address: 0x801C83D0
 * EN v1.0 Size: 1636b
 * EN v1.1 Address: 0x801C8524
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
typedef struct {
    f32 x;
    f32 y;
    f32 z;
} CupVec3;

extern void *Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 *a, f32 *b);
extern int *gPartfxInterface;
extern int *gObjectTriggerInterface;
extern f32 timeDelta;
extern f32 lbl_802C23B8[];

#pragma scheduling off
void ecsh_cup_update(short *obj)
{
    f32 dist;
    int mode;
    u8 buf[4];
    CupVec3 v;
    char *player = (char *)Obj_GetPlayerObject();
    char *state = *(char **)((char *)obj + 0xb8);
    f32 a;

    v = *(CupVec3 *)lbl_802C23B8;
    dist = lbl_803E5064;
    mode = -1;
    buf[0] = 0;
    if (lbl_803DDBC8 == 0) {
        lbl_803DDBC8 = ObjGroup_FindNearestObject(0xb, obj, &dist);
    }
    if (lbl_803DDBC8 != 0 && *(short *)(lbl_803DDBC8 + 0x44) != 0) {
        (*(void (*)(int *, u8 *))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x28))(&mode, buf);
        *obj = *obj + *(s16 *)(state + 0x2c);
        if (mode != 6) {
            *(f32 *)(state + 0x1c) -= timeDelta;
            if (*(f32 *)(state + 0x1c) <= lbl_803E5068) {
                *(f32 *)(state + 0x1c) = lbl_803E506C;
                if (mode != 3 && mode != 6 && mode != 7) {
                    (*(void (*)(short *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x270, 0, 0, -1, 0);
                }
            }
        }
        *(f32 *)(state + 0x20) -= timeDelta;
        if (*(f32 *)(state + 0x20) <= lbl_803E5068) {
            *(s8 *)(state + 0x2e) = *(u8 *)(state + 0x2e) * -1;
            *(f32 *)(state + 0x20) = lbl_803E5070;
        }
        *(f32 *)((char *)obj + 0x10) = lbl_803E5074 * (f32)*(s8 *)(state + 0x2e) + *(f32 *)((char *)obj + 0x10);
        if (mode == 1 && *(int *)(state + 0x24) == 1) {
            *(f32 *)((char *)obj + 0xc) = *(f32 *)(state + 0xc) * timeDelta + *(f32 *)((char *)obj + 0xc);
            *(f32 *)((char *)obj + 0x14) = *(f32 *)(state + 0x14) * timeDelta + *(f32 *)((char *)obj + 0x14);
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        } else {
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        if (mode == 6) {
            if (*(f32 *)((char *)obj + 0x10) < *(f32 *)(state + 0x18)) {
                *(f32 *)((char *)obj + 0x10) = lbl_803E5078 * timeDelta + *(f32 *)((char *)obj + 0x10);
            }
            if (*(u8 *)((char *)obj + 0x37) != 0xff) {
                a = (f32)(u32)*(u8 *)((char *)obj + 0x37);
                a = lbl_803E507C * timeDelta + a;
                if (a >= lbl_803E5080) {
                    a = lbl_803E5080;
                }
                *(u8 *)((char *)obj + 0x37) = (u8)(int)a;
            }
            *(f32 *)(state + 0x1c) -= timeDelta;
            if (*(f32 *)(state + 0x1c) <= lbl_803E5068) {
                *(f32 *)(state + 0x1c) = lbl_803E506C;
                (*(void (*)(short *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x271, 0, 0, -1, 0);
            }
        } else if (mode == 7) {
            if (*(f32 *)((char *)obj + 0x10) > *(f32 *)(state + 0x18) - lbl_803E5084) {
                *(f32 *)((char *)obj + 0x10) = -(lbl_803E5078 * timeDelta - *(f32 *)((char *)obj + 0x10));
                *(f32 *)(state + 0x1c) -= timeDelta;
                if (*(f32 *)(state + 0x1c) <= lbl_803E5068) {
                    *(f32 *)(state + 0x1c) = lbl_803E506C;
                    if (mode != 3) {
                        (*(void (*)(short *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(obj, 0x271, 0, 0, -1, 0);
                    }
                }
            }
            if (*(u8 *)((char *)obj + 0x37) != 0) {
                a = (f32)(u32)*(u8 *)((char *)obj + 0x37);
                a = -(lbl_803E507C * timeDelta - a);
                if (a <= lbl_803E5068) {
                    a = lbl_803E5068;
                }
                *(u8 *)((char *)obj + 0x37) = (u8)(int)a;
            }
        } else if (mode == 8 && mode != *(int *)(state + 0x24)) {
            if (*(int *)(state + 0x28) == buf[0]) {
                (*(void (*)(int, short *, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(0, obj, -1);
            }
            *(int *)(state + 0x24) = mode;
        } else if (mode == 1 && mode != *(int *)(state + 0x24)) {
            (*(void (*)(int, f32 *, f32 *))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x24))((u8)*(int *)(state + 0x28), &v.x, &v.z);
            *(f32 *)(state + 0xc) = (v.x - *(f32 *)((char *)obj + 0xc)) / lbl_803E5070;
            *(f32 *)(state + 0x14) = (v.z - *(f32 *)((char *)obj + 0x14)) / lbl_803E5070;
            *(f32 *)(state + 0) = *(f32 *)((char *)obj + 0xc);
            *(f32 *)(state + 8) = *(f32 *)((char *)obj + 0x14);
            *(int *)(state + 0x24) = mode;
        } else if (mode == 0 && mode != *(int *)(state + 0x24)) {
            *(f32 *)(state + 0xc) = lbl_803E5068;
            *(f32 *)(state + 0x14) = lbl_803E5068;
            *(int *)(state + 0x24) = mode;
        } else if (mode == 2 && mode != *(int *)(state + 0x24)) {
            *(f32 *)(state + 0xc) = lbl_803E5068;
            *(f32 *)(state + 0x14) = lbl_803E5068;
            (*(void (*)(int, f32, f32))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x2c))((u8)*(int *)(state + 0x28), *(f32 *)((char *)obj + 0xc), *(f32 *)((char *)obj + 0x14));
            *(int *)(state + 0x24) = mode;
        } else if (mode == 3 && mode != *(int *)(state + 0x24)) {
            *(int *)(state + 0x24) = mode;
        } else if (mode == 4 && mode != *(int *)(state + 0x24)) {
            (*(void (*)(int, f32 *, f32 *))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x24))((u8)*(int *)(state + 0x28), &v.x, &v.z);
            *(f32 *)((char *)obj + 0xc) = v.x;
            *(f32 *)((char *)obj + 0x14) = v.z;
            *(int *)(state + 0x24) = mode;
        } else if (mode == 5) {
            if (player != NULL) {
                if (Vec_distance((f32 *)((char *)obj + 0x18), (f32 *)(player + 0x18)) < lbl_803E5088) {
                    (*(void (*)(int))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x30))((u8)*(int *)(state + 0x28));
                    if (*(int *)(state + 0x28) == buf[0]) {
                        (*(void (*)(int, short *, int))(*(int *)(*gObjectTriggerInterface + 0x48)))(1, obj, -1);
                    }
                }
            }
        }
    }
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_801c83d4
 * EN v1.0 Address: 0x801C83D4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C864C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c83d4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: ecsh_cup_release
 * EN v1.0 Address: 0x801C8B60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_cup_release(void)
{
}

/*
 * --INFO--
 *
 * Function: ecsh_cup_init
 * EN v1.0 Address: 0x801C8A34
 * EN v1.0 Size: 300b
 */
#pragma peephole off
#pragma scheduling off
void ecsh_cup_init(int obj, int p2)
{
    int t;
    f32 ftmp;

    t = *(int *)(obj + 0xb8);
    ftmp = lbl_803E5064;
    lbl_803DDBC8 = 0;
    *(f32 *)(t + 0x0) = *(f32 *)(obj + 0xc);
    *(f32 *)(t + 0x4) = *(f32 *)(obj + 0x10);
    *(f32 *)(t + 0x8) = *(f32 *)(obj + 0x14);
    *(f32 *)(t + 0x18) = *(f32 *)(obj + 0x10);
    *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x10) - lbl_803E5084;
    {
        f32 fz = lbl_803E5068;
        *(f32 *)(t + 0xc) = fz;
        *(f32 *)(t + 0x10) = fz;
        *(f32 *)(t + 0x14) = fz;
    }
    *(int *)(t + 0x24) = 0;
    *(int *)(t + 0x28) = *(s16 *)(p2 + 0x1a);
    *(f32 *)(t + 0x20) = (f32)randomGetRange(0, 0x258);
    *(s16 *)(t + 0x2c) = (s16)randomGetRange(-0x320, 0x320);
    *(u8 *)(t + 0x2e) = 1;
    *(u8 *)(obj + 0x37) = 0;
    *(f32 *)(t + 0x1c) = lbl_803E5068;
    if (lbl_803DDBC8 == 0) {
        lbl_803DDBC8 = ObjGroup_FindNearestObject(0xb, obj, &ftmp);
    }
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(obj, 0, 0, 0);
    ObjHits_SyncObjectPositionIfDirty(obj);
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: ecsh_cup_initialise
 * EN v1.0 Address: 0x801C8B64
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_cup_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c83fc
 * EN v1.0 Address: 0x801C83FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C8680
 * EN v1.1 Size: 528b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c83fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801c8400
 * EN v1.0 Address: 0x801C8400
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C8890
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c8400(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c8428
 * EN v1.0 Address: 0x801C8428
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x801C8920
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c8428(void)
{
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c845c
 * EN v1.0 Address: 0x801C845C
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801C8950
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c845c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

extern void *Obj_GetPlayerObject(void);
extern f32 fn_80293E80(f32 v);
extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(float *a, float *b);
extern f32 timeDelta;
extern f32 lbl_803E50A0;
extern f32 lbl_803E50A4;
extern f32 lbl_803E50A8;
extern f32 lbl_803E50AC;
extern f32 lbl_803E50B0;
extern f32 lbl_803E50B4;
extern f32 lbl_803E50B8;
extern f32 lbl_803E50BC;
extern f32 lbl_803E50C0;
extern f32 lbl_803E50C4;
extern f32 lbl_803E50C8;
extern f64 lbl_803E50D0;

/*
 * --INFO--
 *
 * Function: fn_801C8B68
 * EN v1.0 Address: 0x801C8B68
 * EN v1.0 Size: 852b
 */
#pragma peephole off
#pragma scheduling off
void fn_801C8B68(int obj)
{
    register int self = obj;
    register int state2 = *(int *)(self + 0x4c);
    register int state = *(int *)(self + 0xb8);
    void *player = Obj_GetPlayerObject();
    int local_var;
    f32 dist;
    f32 angA, angB;
    int delta;

    if ((*(short *)(self + 0x6) & 0x4000) != 0) {
        *(short *)self = 0;
        *(float *)(self + 0x10) = *(float *)(state2 + 0xc);
        return;
    }

    *(short *)(state + 0xe) = (short)(
        (int)*(short *)(state + 0xe)
        + (int)(lbl_803E50A0 * timeDelta));
    *(short *)(state + 0x10) = (short)(
        (int)*(short *)(state + 0x10)
        + (int)(lbl_803E50A4 * timeDelta));
    *(short *)(state + 0x12) = (short)(
        (int)*(short *)(state + 0x12)
        + (int)(lbl_803E50A8 * timeDelta));

    *(float *)(self + 0x10) = lbl_803E50AC + (*(float *)(state2 + 0xc) +
        fn_80293E80((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4));
    angA = fn_80293E80((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0x10)) / lbl_803E50B4);
    angB = fn_80293E80((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4);
    *(short *)(self + 0x4) = (short)(int)(lbl_803E50B8 * (angA + angB));
    angA = fn_80293E80((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0x12)) / lbl_803E50B4);
    angB = fn_80293E80((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4);
    *(short *)(self + 0x2) = (short)(int)(lbl_803E50B8 * (angA + angB));

    ObjAnim_AdvanceCurrentMove(lbl_803E50BC, timeDelta, self, (ObjAnimEventList *)&local_var);

    if (player == NULL) return;

    {
        float dx = *(float *)(self + 0x18) - *(float *)((int)player + 0x18);
        float dz = *(float *)(self + 0x20) - *(float *)((int)player + 0x20);
        int ang = (int)getAngle(dx, dz);
        delta = (int)(u16)ang - (int)(u16)*(short *)self;
        if (delta > 0x8000) delta -= 0x10000;
        if (delta < -0x8000) delta += 0x10000;
        *(short *)self = (short)(
            (int)*(short *)self
            + (int)((f32)delta * timeDelta / lbl_803E50C0));
    }
    dist = Vec_xzDistance((float *)(self + 0x18), (float *)((int)player + 0x18));
    if (dist <= lbl_803E50C4) {
        *(u8 *)(self + 0x36) = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    } else {
        *(u8 *)(self + 0x36) = 0xff;
    }
}
#pragma scheduling reset
#pragma peephole reset
