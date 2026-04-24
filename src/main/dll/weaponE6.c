#include "ghidra_import.h"
#include "main/dll/weaponE6.h"

extern bool FUN_8000b598();
extern uint FUN_80020078();
extern int FUN_80021850();
extern uint FUN_80022264();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_800394f0();
extern int FUN_8005a288();
extern undefined4 FUN_8013a778();
extern int FUN_8013b6f0();
extern int FUN_80144994();
extern undefined4 FUN_80148fa0();
extern undefined4 FUN_80148ff0();
extern int FUN_80163d68();
extern uint FUN_80179850();
extern undefined4 FUN_80179af4();
extern int FUN_80179b18();
extern undefined4 FUN_80179b40();
extern undefined4 FUN_80179b84();
extern undefined4 FUN_801ce424();
extern double FUN_80293900();
extern undefined4 FUN_80293bc4();
extern undefined4 FUN_802940dc();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern f64 DOUBLE_803e30f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e3098;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e310c;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e3138;
extern f32 FLOAT_803e3158;
extern f32 FLOAT_803e3160;
extern f32 FLOAT_803e3164;
extern f32 FLOAT_803e317c;
extern f32 FLOAT_803e3180;
extern f32 FLOAT_803e3184;
extern f32 FLOAT_803e3188;
extern f32 FLOAT_803e318c;
extern f32 FLOAT_803e3190;

/*
 * --INFO--
 *
 * Function: FUN_8013f314
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8013F314
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013f314(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,int param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  
  iVar1 = FUN_80021850();
  if (*(char *)(param_10 + 10) == '\0') {
    uVar2 = FUN_80022264(0,1);
    *(uint *)(param_10 + 0x700) = uVar2;
    if (*(int *)(param_10 + 0x700) == 0) {
      *(undefined4 *)(param_10 + 0x700) = 0xffffffff;
    }
    *(int *)(param_10 + 0x704) = iVar1;
    *(undefined *)(param_10 + 10) = 1;
  }
  iVar1 = iVar1 - (*(uint *)(param_10 + 0x704) & 0xffff);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  if (iVar1 < 0x2000) {
    *(int *)(param_10 + 0x704) = *(int *)(param_10 + 0x704) + *(int *)(param_10 + 0x700) * 0x800;
  }
  dVar3 = (double)FUN_80293bc4();
  *(float *)(param_10 + 0x708) =
       -(float)((double)FLOAT_803e3164 * dVar3 -
               (double)*(float *)(*(int *)(param_10 + 0x24) + 0x18));
  *(undefined4 *)(param_10 + 0x70c) = *(undefined4 *)(*(int *)(param_10 + 0x24) + 0x1c);
  dVar3 = (double)FUN_802940dc();
  dVar4 = (double)FLOAT_803e3164;
  *(float *)(param_10 + 0x710) =
       -(float)(dVar4 * dVar3 - (double)*(float *)(*(int *)(param_10 + 0x24) + 0x20));
  iVar1 = FUN_8013b6f0((double)FLOAT_803e3118,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,
                       param_9,param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  if (iVar1 == 0) {
    FUN_80148fa0();
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013f488
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8013F488
 * EN v1.1 Size: 2276b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013f488(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,undefined4 param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8013fd6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8013FD6C
 * EN v1.1 Size: 512b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013fd6c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  uint uVar3;
  bool bVar4;
  
  iVar2 = FUN_80144994(param_9,param_10);
  if ((iVar2 == 0) &&
     (iVar2 = FUN_8013b6f0((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                           param_16), iVar2 == 0)) {
    param_10[0x1d0] = (int)((float)param_10[0x1d0] - FLOAT_803dc074);
    if ((float)param_10[0x1d0] <= FLOAT_803e306c) {
      uVar3 = FUN_80022264(500,0x2ee);
      param_10[0x1d0] =
           (int)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e30f0);
      iVar2 = *(int *)(param_9 + 0xb8);
      if (((*(byte *)(iVar2 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
          (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)))) {
        FUN_800394f0(param_9,iVar2 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
    if (FLOAT_803e306c == (float)param_10[0xab]) {
      bVar4 = false;
    }
    else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
      bVar4 = true;
    }
    else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
      bVar4 = false;
    }
    else {
      bVar4 = true;
    }
    if (bVar4) {
      FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
      param_10[0x1e7] = (int)FLOAT_803e30d0;
      param_10[0x20e] = (int)FLOAT_803e306c;
      FUN_80148ff0();
    }
    else {
      sVar1 = *(short *)(param_9 + 0xa0);
      if (sVar1 != 0x31) {
        if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
          if ((param_10[0x15] & 0x8000000U) != 0) {
            FUN_8013a778((double)FLOAT_803e30cc,param_9,0x31,0);
          }
        }
        else {
          FUN_8013a778((double)FLOAT_803e30d4,param_9,0xd,0);
        }
      }
      FUN_80148ff0();
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013ff6c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8013FF6C
 * EN v1.1 Size: 732b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013ff6c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 *param_10,undefined4 param_11,undefined4 param_12,
                 byte param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80140248
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80140248
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80140248(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)
{
  bool bVar1;
  int iVar2;
  
  iVar2 = FUN_8013b6f0((double)FLOAT_803e310c,param_2,param_3,param_4,param_5,param_6,param_7,
                       param_8,param_9,param_10,param_11,param_12,param_13,param_14,param_15,
                       param_16);
  if (iVar2 == 0) {
    if (FLOAT_803e306c == *(float *)(param_10 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(param_10 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(param_10 + 0x2b4) - *(float *)(param_10 + 0x2b0) <= FLOAT_803e30a4) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
      *(float *)(param_10 + 0x79c) = FLOAT_803e30d0;
      *(float *)(param_10 + 0x838) = FLOAT_803e306c;
      FUN_80148ff0();
    }
    else {
      FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
      FUN_80148ff0();
    }
  }
  return;
}
