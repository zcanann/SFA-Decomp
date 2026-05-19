#include "ghidra_import.h"
#include "main/dll/dll_1C5.h"

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
extern undefined4 DAT_803de848;
extern f64 DOUBLE_803e5d28;
extern f64 DOUBLE_803e5d30;
extern f32 lbl_803DC074;
extern f32 lbl_803E5CE4;
extern f32 lbl_803E5CE8;
extern f32 lbl_803E5CFC;
extern f32 lbl_803E5D00;
extern f32 lbl_803E5D04;
extern f32 lbl_803E5D08;
extern f32 lbl_803E5D0C;
extern f32 lbl_803E5D10;
extern f32 lbl_803E5D14;
extern f32 lbl_803E5D18;
extern f32 lbl_803E5D1C;
extern f32 lbl_803E5D20;

extern f32 lbl_803E5064;
extern f32 lbl_803E5068;
extern f32 lbl_803E5084;
extern undefined4 lbl_803DDBC8;
extern int randomGetRange(int min, int max);

/*
 * --INFO--
 *
 * Function: ecsh_cup_update
 * EN v1.0 Address: 0x801C83D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801C8524
 * EN v1.1 Size: 296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ecsh_cup_update(undefined2 *param_1)
{
}

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
void FUN_801c83d4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
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
void FUN_801c8400(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
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
void FUN_801c845c(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801c8484
 * EN v1.0 Address: 0x801C8484
 * EN v1.0 Size: 2120b
 * EN v1.1 Address: 0x801C8984
 * EN v1.1 Size: 1636b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801c8484(short *param_1)
{
  float fVar1;
  int iVar2;
  undefined4 *puVar3;
  double dVar4;
  byte local_38 [4];
  int local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  float local_24;
  undefined8 local_20;
  undefined8 local_18;
  
  iVar2 = FUN_80017a98();
  puVar3 = *(undefined4 **)(param_1 + 0x5c);
  local_2c = DAT_802c2b38;
  local_28 = DAT_802c2b3c;
  local_24 = DAT_802c2b40;
  local_30 = lbl_803E5CFC;
  local_34 = -1;
  local_38[0] = 0;
  if (DAT_803de848 == 0) {
    DAT_803de848 = ObjGroup_FindNearestObject(0xb,param_1,&local_30);
  }
  if ((DAT_803de848 != 0) && (*(short *)(DAT_803de848 + 0x44) != 0)) {
    (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x28))(&local_34,local_38);
    *param_1 = *param_1 + *(short *)(puVar3 + 0xb);
    if (((local_34 != 6) &&
        (((puVar3[7] = (float)puVar3[7] - lbl_803DC074, (float)puVar3[7] <= lbl_803E5D00 &&
          (puVar3[7] = lbl_803E5D04, local_34 != 3)) && (local_34 != 6)))) && (local_34 != 7)) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x270,0,0,0xffffffff,0);
    }
    puVar3[8] = (float)puVar3[8] - lbl_803DC074;
    if ((float)puVar3[8] <= lbl_803E5D00) {
      *(char *)((int)puVar3 + 0x2e) = -*(char *)((int)puVar3 + 0x2e);
      puVar3[8] = lbl_803E5D08;
    }
    local_20 = (double)CONCAT44(0x43300000,(int)*(char *)((int)puVar3 + 0x2e) ^ 0x80000000);
    *(float *)(param_1 + 8) =
         lbl_803E5D0C * (float)(local_20 - DOUBLE_803e5d28) + *(float *)(param_1 + 8);
    if ((local_34 == 1) && (puVar3[9] == 1)) {
      *(float *)(param_1 + 6) = (float)puVar3[3] * lbl_803DC074 + *(float *)(param_1 + 6);
      *(float *)(param_1 + 10) = (float)puVar3[5] * lbl_803DC074 + *(float *)(param_1 + 10);
      ObjHits_EnableObject((int)param_1);
      ObjHits_SetHitVolumeSlot((int)param_1,10,1,0);
      ObjHits_SyncObjectPositionIfDirty((int)param_1);
    }
    else {
      ObjHits_EnableObject((int)param_1);
      ObjHits_SetHitVolumeSlot((int)param_1,0,0,0);
      ObjHits_SyncObjectPositionIfDirty((int)param_1);
    }
    fVar1 = lbl_803E5D00;
    if (local_34 == 6) {
      if (*(float *)(param_1 + 8) < (float)puVar3[6]) {
        *(float *)(param_1 + 8) = lbl_803E5D10 * lbl_803DC074 + *(float *)(param_1 + 8);
      }
      if (*(byte *)((int)param_1 + 0x37) != 0xff) {
        local_20 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_1 + 0x37));
        fVar1 = lbl_803E5D14 * lbl_803DC074 + (float)(local_20 - DOUBLE_803e5d30);
        if (lbl_803E5D18 <= fVar1) {
          fVar1 = lbl_803E5D18;
        }
        local_18 = (double)(longlong)(int)fVar1;
        *(char *)((int)param_1 + 0x37) = (char)(int)fVar1;
      }
      puVar3[7] = (float)puVar3[7] - lbl_803DC074;
      if ((float)puVar3[7] <= lbl_803E5D00) {
        puVar3[7] = lbl_803E5D04;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x271,0,0,0xffffffff,0);
      }
    }
    else if (local_34 == 7) {
      if ((float)puVar3[6] - lbl_803E5D1C < *(float *)(param_1 + 8)) {
        *(float *)(param_1 + 8) = -(lbl_803E5D10 * lbl_803DC074 - *(float *)(param_1 + 8));
        puVar3[7] = (float)puVar3[7] - lbl_803DC074;
        if ((float)puVar3[7] <= lbl_803E5D00) {
          puVar3[7] = lbl_803E5D04;
          (**(code **)(*DAT_803dd708 + 8))(param_1,0x271,0,0,0xffffffff,0);
        }
      }
      if (*(byte *)((int)param_1 + 0x37) != 0) {
        local_18 = (double)CONCAT44(0x43300000,(uint)*(byte *)((int)param_1 + 0x37));
        fVar1 = -(lbl_803E5D14 * lbl_803DC074 - (float)(local_18 - DOUBLE_803e5d30));
        if (fVar1 <= lbl_803E5D00) {
          fVar1 = lbl_803E5D00;
        }
        *(char *)((int)param_1 + 0x37) = (char)(int)fVar1;
      }
    }
    else if ((local_34 == 8) && (puVar3[9] != 8)) {
      if (puVar3[10] == (uint)local_38[0]) {
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
      }
      puVar3[9] = local_34;
    }
    else if ((local_34 == 1) && (puVar3[9] != 1)) {
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x24))(puVar3[10] & 0xff,&local_2c,&local_24);
      fVar1 = lbl_803E5D08;
      puVar3[3] = (local_2c - *(float *)(param_1 + 6)) / lbl_803E5D08;
      puVar3[5] = (local_24 - *(float *)(param_1 + 10)) / fVar1;
      *puVar3 = *(undefined4 *)(param_1 + 6);
      puVar3[2] = *(undefined4 *)(param_1 + 10);
      puVar3[9] = local_34;
    }
    else if ((local_34 == 0) && (puVar3[9] != 0)) {
      puVar3[3] = lbl_803E5D00;
      puVar3[5] = fVar1;
      puVar3[9] = 0;
    }
    else if ((local_34 == 2) && (puVar3[9] != 2)) {
      puVar3[3] = lbl_803E5D00;
      puVar3[5] = fVar1;
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x2c))
                ((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 10),puVar3[10] & 0xff)
      ;
      puVar3[9] = local_34;
    }
    else if ((local_34 == 3) && (puVar3[9] != 3)) {
      puVar3[9] = 3;
    }
    else if ((local_34 == 4) && (puVar3[9] != 4)) {
      (**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x24))(puVar3[10] & 0xff,&local_2c,&local_24);
      *(float *)(param_1 + 6) = local_2c;
      *(float *)(param_1 + 10) = local_24;
      puVar3[9] = local_34;
    }
    else if ((((local_34 == 5) && (iVar2 != 0)) &&
             (dVar4 = (double)FUN_8001771c((float *)(param_1 + 0xc),(float *)(iVar2 + 0x18)),
             dVar4 < (double)lbl_803E5D20)) &&
            ((**(code **)(**(int **)(DAT_803de848 + 0x68) + 0x30))(puVar3[10] & 0xff),
            puVar3[10] == (uint)local_38[0])) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
    }
  }
  return;
}

extern void *Obj_GetPlayerObject(void);
extern double fn_80293E80(double v);
extern void ObjAnim_AdvanceCurrentMove(int obj, void *p2, float f1, float f2);
extern double getAngle(float dx, float dz);
extern double Vec_xzDistance(float *a, float *b);
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
    double dist;
    double angA, angB;
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
        fn_80293E80((double)((lbl_803E50B0 * ((double)(int)*(short *)(state + 0xe) - lbl_803E50D0)) / lbl_803E50B4)));
    angA = fn_80293E80((double)((lbl_803E50B0 * ((double)(int)*(short *)(state + 0x10) - lbl_803E50D0)) / lbl_803E50B4));
    angB = fn_80293E80((double)((lbl_803E50B0 * ((double)(int)*(short *)(state + 0xe) - lbl_803E50D0)) / lbl_803E50B4));
    *(short *)(self + 0x4) = (short)(int)(lbl_803E50B8 * (angA + angB));
    angA = fn_80293E80((double)((lbl_803E50B0 * ((double)(int)*(short *)(state + 0x12) - lbl_803E50D0)) / lbl_803E50B4));
    angB = fn_80293E80((double)((lbl_803E50B0 * ((double)(int)*(short *)(state + 0xe) - lbl_803E50D0)) / lbl_803E50B4));
    *(short *)(self + 0x2) = (short)(int)(lbl_803E50B8 * (angA + angB));

    ObjAnim_AdvanceCurrentMove(self, &local_var, lbl_803E50BC, timeDelta);

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
            + (int)((float)((double)delta - lbl_803E50D0) * timeDelta / lbl_803E50C0));
    }
    dist = Vec_xzDistance((float *)(self + 0x18), (float *)((int)player + 0x18));
    if (dist <= (double)lbl_803E50C4) {
        *(u8 *)(self + 0x36) = (u8)(int)(lbl_803E50C8 * (dist / lbl_803E50C4));
    } else {
        *(u8 *)(self + 0x36) = 0xff;
    }
}
#pragma scheduling reset
#pragma peephole reset
