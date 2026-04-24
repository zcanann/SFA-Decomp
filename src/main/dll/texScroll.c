#include "ghidra_import.h"
#include "main/dll/texScroll.h"

extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern undefined4 FUN_80035a6c();
extern uint FUN_80036974();
extern undefined4 FUN_800395a4();
extern int FUN_80080284();

extern undefined4 DAT_80321c58;
extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e43b8;
extern f64 DOUBLE_803e43d8;
extern f64 DOUBLE_803e43e0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e43c0;
extern f32 FLOAT_803e43c8;
extern f32 FLOAT_803e43cc;
extern f32 FLOAT_803e43d0;
extern f32 FLOAT_803e43d4;
extern f32 FLOAT_803e43e8;

/*
 * --INFO--
 *
 * Function: FUN_8017ac40
 * EN v1.0 Address: 0x8017AC2C
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x8017AC40
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ac40(short *param_1,int param_2)
{
  uint uVar1;
  undefined4 *puVar2;
  int iVar3;
  char *pcVar4;
  undefined *puVar5;
  
  pcVar4 = *(char **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1f) << 8;
  param_1[1] = (ushort)*(byte *)(param_2 + 0x1c) << 8;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 4) = *(undefined4 *)(*(int *)(param_1 + 0x28) + 4);
  }
  else {
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e43b8) *
         *(float *)(*(int *)(param_1 + 0x28) + 4) * FLOAT_803e43c0;
  }
  FUN_80035a6c((int)param_1,
               (short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                            (uint)*(byte *)(*(int *)(param_1 + 0x28) + 0x62)) >> 6));
  *(char *)((int)param_1 + 0xad) = (char)((int)(uint)*(byte *)(param_2 + 0x1e) >> 2);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  if (*(int *)(param_1 + 0x18) == 0) {
    *(undefined2 *)(pcVar4 + 2) = *(undefined2 *)(param_2 + 0x18);
  }
  else {
    iVar3 = *(int *)(*(int *)(param_1 + 0x18) + 0x4c);
    if (iVar3 == 0) {
      pcVar4[2] = -1;
      pcVar4[3] = -1;
    }
    else {
      iVar3 = FUN_80080284((int *)&DAT_80321c58,2,*(int *)(iVar3 + 0x14));
      *(short *)(pcVar4 + 2) = (short)iVar3;
    }
  }
  uVar1 = FUN_80020078((int)*(short *)(pcVar4 + 2));
  *pcVar4 = (char)uVar1;
  if (*pcVar4 == '\0') {
    puVar5 = *(undefined **)(param_1 + 0x5c);
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
    *puVar5 = 0;
  }
  else {
    puVar5 = *(undefined **)(param_1 + 0x5c);
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
    *puVar5 = 1;
  }
  if ((*(byte *)(param_2 + 0x23) & 1) == 0) {
    param_1[0x58] = param_1[0x58] | 0x4000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017ae38
 * EN v1.0 Address: 0x8017ADF0
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x8017AE38
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017ae38(int param_1)
{
  float fVar1;
  uint uVar2;
  char *pcVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pcVar3 = *(char **)(param_1 + 0xb8);
  if (*pcVar3 == '\0') {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x18));
    if (uVar2 != 0) {
      *pcVar3 = '\x01';
    }
  }
  else {
    uVar2 = FUN_80020078((int)*(short *)(iVar4 + 0x18));
    if (uVar2 == 0) {
      *pcVar3 = '\0';
    }
  }
  fVar1 = FLOAT_803e43c8;
  if (FLOAT_803e43c8 < *(float *)(pcVar3 + 4)) {
    *(float *)(pcVar3 + 4) =
         *(float *)(pcVar3 + 4) -
         (float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e43d8);
    if (fVar1 < *(float *)(pcVar3 + 4)) {
      return;
    }
    *(float *)(pcVar3 + 4) = fVar1;
    FUN_800201ac((int)*(short *)(iVar4 + 0x18),0);
  }
  if (*(float *)(pcVar3 + 8) == FLOAT_803e43c8) {
    uVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
    if ((byte)pcVar3[1] == uVar2) {
      if (*pcVar3 == '\0') {
        if ((*(byte *)(iVar4 + 0x1e) & 3) == 3) {
          *(float *)(pcVar3 + 8) = FLOAT_803e43d0;
        }
        else {
          *pcVar3 = '\x01';
          FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
          if ((*(byte *)(iVar4 + 0x1e) & 3) == 2) {
            *(float *)(pcVar3 + 4) =
                 FLOAT_803e43cc *
                 FLOAT_803e43d4 *
                 (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 0x1a) ^ 0x80000000) -
                        DOUBLE_803e43e0);
          }
        }
      }
      else if ((*(byte *)(iVar4 + 0x1e) & 3) == 1) {
        *pcVar3 = '\0';
        FUN_800201ac((int)*(short *)(iVar4 + 0x18),0);
      }
    }
  }
  else {
    *(float *)(pcVar3 + 8) = *(float *)(pcVar3 + 8) - FLOAT_803dc074;
    if (*(float *)(pcVar3 + 8) < FLOAT_803e43cc) {
      uVar2 = FUN_80036974(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0);
      if ((byte)pcVar3[1] == uVar2) {
        *(float *)(pcVar3 + 8) = FLOAT_803e43c8;
        *pcVar3 = '\x01';
        FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
      }
      else if (*(float *)(pcVar3 + 8) <= FLOAT_803e43c8) {
        *(float *)(pcVar3 + 8) = FLOAT_803e43c8;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b064
 * EN v1.0 Address: 0x8017B028
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x8017B064
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8017b064(int param_1,int param_2)
{
  uint uVar1;
  undefined *puVar2;
  
  puVar2 = *(undefined **)(param_1 + 0xb8);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x6000;
  if (*(byte *)(param_2 + 0x1d) == 0) {
    *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*(int *)(param_1 + 0x50) + 4);
  }
  else {
    *(float *)(param_1 + 8) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x1d)) - DOUBLE_803e43d8) *
         *(float *)(*(int *)(param_1 + 0x50) + 4) * FLOAT_803e43e8;
  }
  FUN_80035a6c(param_1,(short)((int)((uint)*(byte *)(param_2 + 0x1d) *
                                    (uint)*(byte *)(*(int *)(param_1 + 0x50) + 0x62)) >> 6));
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  *puVar2 = (char)uVar1;
  uVar1 = (int)(*(byte *)(param_2 + 0x23) & 0xe) >> 1;
  if (uVar1 == 1) {
    puVar2[1] = 0x10;
  }
  else if ((uVar1 == 0) || (2 < uVar1)) {
    puVar2[1] = 5;
  }
  else {
    puVar2[1] = 0x15;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8017b170
 * EN v1.0 Address: 0x8017B130
 * EN v1.0 Size: 356b
 * EN v1.1 Address: 0x8017B170
 * EN v1.1 Size: 348b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8017b170(int param_1,undefined4 param_2,int param_3)
{
  short sVar1;
  int iVar2;
  int iVar3;
  byte bVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_3 + 0x80) == '\x01') {
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 1) {
      iVar2 = (uint)bVar4 * 4 + 4;
      iVar6 = *(int *)(iVar7 + iVar2);
      if (iVar6 != 0) {
        iVar3 = iVar7 + (uint)bVar4 * 8;
        *(undefined4 *)(iVar3 + 0x2c) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(iVar3 + 0x30) = *(undefined4 *)(*(int *)(iVar7 + iVar2) + 0x14);
      }
    }
    *(undefined *)(param_3 + 0x80) = 0;
  }
  else if (*(char *)(param_3 + 0x80) == '\x02') {
    for (bVar4 = 0; bVar4 < 10; bVar4 = bVar4 + 5) {
      puVar5 = (undefined4 *)(iVar7 + (uint)bVar4 * 4 + 4);
      *puVar5 = 0;
      puVar5[1] = 0;
      puVar5[2] = 0;
      puVar5[3] = 0;
      puVar5[4] = 0;
    }
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar7 + 0x7c);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar6 + 0x10);
    FUN_800201ac((int)*(short *)(iVar6 + 0x1a),0);
    *(undefined *)(param_3 + 0x80) = 0;
  }
  sVar1 = *(short *)(param_1 + 0x46);
  if ((((sVar1 != 0x19f) && (sVar1 != 0x26c)) && (sVar1 != 0x274)) && (sVar1 != 0x545)) {
    *(undefined4 *)(iVar7 + 0x7c) = *(undefined4 *)(param_1 + 0x10);
  }
  return 0;
}
