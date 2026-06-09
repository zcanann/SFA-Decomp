#include "main/dll/dimbarrier.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objseq.h"

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
extern EffectInterface **gPartfxInterface;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern f32 timeDelta;
extern f32 lbl_802C23B8[];

#pragma peephole on
void ecsh_cup_update(short *obj)
{
    f32 dist;
    int mode;
    u8 buf[4];
    CupVec3 v;
    char *player = (char *)Obj_GetPlayerObject();
    char *state = ((GameObject *)obj)->extra;
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
                    (*gPartfxInterface)->spawnObject(obj, 0x270, NULL, 0, -1, NULL);
                }
            }
        }
        *(f32 *)(state + 0x20) -= timeDelta;
        if (*(f32 *)(state + 0x20) <= lbl_803E5068) {
            *(s8 *)(state + 0x2e) = *(u8 *)(state + 0x2e) * -1;
            *(f32 *)(state + 0x20) = lbl_803E5070;
        }
        ((GameObject *)obj)->anim.localPosY = lbl_803E5074 * (f32)*(s8 *)(state + 0x2e) + ((GameObject *)obj)->anim.localPosY;
        if (mode == 1 && *(int *)(state + 0x24) == 1) {
            ((GameObject *)obj)->anim.localPosX = *(f32 *)(state + 0xc) * timeDelta + ((GameObject *)obj)->anim.localPosX;
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)(state + 0x14) * timeDelta + ((GameObject *)obj)->anim.localPosZ;
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        } else {
            ObjHits_EnableObject((int)obj);
            ObjHits_SetHitVolumeSlot((int)obj, 0, 0, 0);
            ObjHits_SyncObjectPositionIfDirty((int)obj);
        }
        if (mode == 6) {
            if (((GameObject *)obj)->anim.localPosY < *(f32 *)(state + 0x18)) {
                ((GameObject *)obj)->anim.localPosY = lbl_803E5078 * timeDelta + ((GameObject *)obj)->anim.localPosY;
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
                (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
            }
        } else if (mode == 7) {
            if (((GameObject *)obj)->anim.localPosY > *(f32 *)(state + 0x18) - lbl_803E5084) {
                ((GameObject *)obj)->anim.localPosY = -(lbl_803E5078 * timeDelta - ((GameObject *)obj)->anim.localPosY);
                *(f32 *)(state + 0x1c) -= timeDelta;
                if (*(f32 *)(state + 0x1c) <= lbl_803E5068) {
                    *(f32 *)(state + 0x1c) = lbl_803E506C;
                    if (mode != 3) {
                        (*gPartfxInterface)->spawnObject(obj, 0x271, NULL, 0, -1, NULL);
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
                (*gObjectTriggerInterface)->runSequence(0, (void *)obj, -1);
            }
            *(int *)(state + 0x24) = mode;
        } else if (mode == 1 && mode != *(int *)(state + 0x24)) {
            (*(void (*)(int, f32 *, f32 *))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x24))((u8)*(int *)(state + 0x28), &v.x, &v.z);
            *(f32 *)(state + 0xc) = (v.x - ((GameObject *)obj)->anim.localPosX) / lbl_803E5070;
            *(f32 *)(state + 0x14) = (v.z - ((GameObject *)obj)->anim.localPosZ) / lbl_803E5070;
            *(f32 *)(state + 0) = ((GameObject *)obj)->anim.localPosX;
            *(f32 *)(state + 8) = ((GameObject *)obj)->anim.localPosZ;
            *(int *)(state + 0x24) = mode;
        } else if (mode == 0 && mode != *(int *)(state + 0x24)) {
            *(f32 *)(state + 0xc) = lbl_803E5068;
            *(f32 *)(state + 0x14) = lbl_803E5068;
            *(int *)(state + 0x24) = mode;
        } else if (mode == 2 && mode != *(int *)(state + 0x24)) {
            *(f32 *)(state + 0xc) = lbl_803E5068;
            *(f32 *)(state + 0x14) = lbl_803E5068;
            (*(void (*)(int, f32, f32))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x2c))((u8)*(int *)(state + 0x28), ((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosZ);
            *(int *)(state + 0x24) = mode;
        } else if (mode == 3 && mode != *(int *)(state + 0x24)) {
            *(int *)(state + 0x24) = mode;
        } else if (mode == 4 && mode != *(int *)(state + 0x24)) {
            (*(void (*)(int, f32 *, f32 *))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x24))((u8)*(int *)(state + 0x28), &v.x, &v.z);
            ((GameObject *)obj)->anim.localPosX = v.x;
            ((GameObject *)obj)->anim.localPosZ = v.z;
            *(int *)(state + 0x24) = mode;
        } else if (mode == 5) {
            if (player != NULL) {
                if (Vec_distance(&((GameObject *)obj)->anim.worldPosX, (f32 *)(player + 0x18)) < lbl_803E5088) {
                    (*(void (*)(int))*(int *)(*(int *)(*(int *)(lbl_803DDBC8 + 0x68)) + 0x30))((u8)*(int *)(state + 0x28));
                    if (*(int *)(state + 0x28) == buf[0]) {
                        (*gObjectTriggerInterface)->runSequence(1, (void *)obj, -1);
                    }
                }
            }
        }
    }
}
#pragma peephole reset

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
#pragma scheduling on
#pragma peephole on
void FUN_801c83d4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
void ecsh_cup_init(int obj, int p2)
{
    int t;
    f32 ftmp;

    t = *(int *)&((GameObject *)obj)->extra;
    ftmp = lbl_803E5064;
    lbl_803DDBC8 = 0;
    *(f32 *)(t + 0x0) = ((GameObject *)obj)->anim.localPosX;
    *(f32 *)(t + 0x4) = ((GameObject *)obj)->anim.localPosY;
    *(f32 *)(t + 0x8) = ((GameObject *)obj)->anim.localPosZ;
    *(f32 *)(t + 0x18) = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E5084;
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
#pragma scheduling on
#pragma peephole on
void FUN_801c8400(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
void FUN_801c8428(int obj)
{
  (*gExpgfxInterface)->freeSource2((u32)obj);
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
#pragma scheduling on
#pragma peephole on
void FUN_801c845c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

extern f32 mathSinf(f32 v);
extern int getAngle(f32 dx, f32 dz);
extern f32 Vec_xzDistance(float *a, float *b);
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
void fn_801C8B68(int obj)
{
    register int self = obj;
    register int state2 = *(int *)&((GameObject *)self)->anim.placementData;
    register int state = *(int *)&((GameObject *)self)->extra;
    void *player = Obj_GetPlayerObject();
    int local_var;
    f32 dist;
    f32 angA, angB;
    int delta;

    if ((((GameObject *)self)->anim.flags & 0x4000) != 0) {
        *(short *)self = 0;
        ((GameObject *)self)->anim.localPosY = *(float *)(state2 + 0xc);
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

    ((GameObject *)self)->anim.localPosY = lbl_803E50AC + (*(float *)(state2 + 0xc) +
        mathSinf((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4));
    angA = mathSinf((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0x10)) / lbl_803E50B4);
    angB = mathSinf((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4);
    ((GameObject *)self)->anim.rotZ = (short)(int)(lbl_803E50B8 * (angA + angB));
    angA = mathSinf((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0x12)) / lbl_803E50B4);
    angB = mathSinf((lbl_803E50B0 * (f32)(s32)*(short *)(state + 0xe)) / lbl_803E50B4);
    ((GameObject *)self)->anim.rotY = (short)(int)(lbl_803E50B8 * (angA + angB));

    ObjAnim_AdvanceCurrentMove(lbl_803E50BC, timeDelta, self, (ObjAnimEventList *)&local_var);

    if (player == NULL) return;

    {
        float dx = ((GameObject *)self)->anim.worldPosX - *(float *)((int)player + 0x18);
        float dz = ((GameObject *)self)->anim.worldPosZ - *(float *)((int)player + 0x20);
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
        ((GameObject *)self)->anim.alpha = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    } else {
        ((GameObject *)self)->anim.alpha = 0xff;
    }
}
