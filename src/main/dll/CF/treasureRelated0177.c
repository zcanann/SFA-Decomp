#include "ghidra_import.h"
#include "main/dll/CF/treasureRelated0177.h"

extern undefined8 FUN_8000d03c();
extern undefined4 FUN_8000d220();
extern undefined4 FUN_8000dbb0();
extern undefined4 FUN_8000dcdc();
extern void* FUN_8000facc();
extern undefined4 FUN_8000fc5c();
extern undefined4 FUN_8001dc30();
extern undefined4 FUN_8001f448();
extern undefined4 FUN_8001ff38();
extern undefined4 FUN_800207ac();
extern double FUN_80021434();
extern uint FUN_80022264();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_8002fb40();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80035ea4();
extern undefined4 FUN_80035eec();
extern undefined4 FUN_800395a4();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80055220();
extern undefined8 FUN_8005d0e4();
extern undefined4 FUN_80060630();
extern undefined4 FUN_80098da4();
extern undefined4 FUN_800d7cfc();
extern undefined4 FUN_8011e06c();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();
extern byte FUN_802973bc();
extern undefined4 FUN_802973cc();
extern void* SUB42();

extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6f8;
extern f64 DOUBLE_803e4a08;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e49b0;
extern f32 FLOAT_803e49b4;
extern f32 FLOAT_803e49b8;
extern f32 FLOAT_803e49bc;
extern f32 FLOAT_803e49c0;
extern f32 FLOAT_803e49c4;
extern f32 FLOAT_803e49d0;
extern f32 FLOAT_803e49dc;
extern f32 FLOAT_803e49e0;
extern f32 FLOAT_803e49f0;
extern f32 FLOAT_803e49fc;
extern f32 FLOAT_803e4a00;
extern f32 FLOAT_803e4a10;
extern f32 FLOAT_803e4a14;
extern f32 FLOAT_803e4a18;

/*
 * --INFO--
 *
 * Function: FUN_8018cdac
 * EN v1.0 Address: 0x8018CDAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018CDAC
 * EN v1.1 Size: 1116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018cdac(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8018d208
 * EN v1.0 Address: 0x8018CDB0
 * EN v1.0 Size: 424b
 * EN v1.1 Address: 0x8018D208
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d208(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  short *psVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_9 + 0xb8);
  psVar2 = FUN_8000facc();
  FUN_800d7cfc(1);
  (**(code **)(*DAT_803dd6cc + 8))(1,1);
  FUN_8003042c((double)FLOAT_803e49b4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               param_9,0x8e,0,param_12,param_13,param_14,param_15,param_16);
  *pfVar3 = FLOAT_803e49f0;
  pfVar3[1] = *(float *)(psVar2 + 6);
  pfVar3[2] = *(float *)(psVar2 + 8);
  pfVar3[3] = *(float *)(psVar2 + 10);
  pfVar3[6] = (float)(int)*psVar2;
  pfVar3[7] = (float)(int)psVar2[1];
  fVar1 = FLOAT_803e49c4;
  pfVar3[4] = FLOAT_803e49c4;
  pfVar3[5] = fVar1;
  FUN_8001ff38(param_9);
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x400;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d2f4
 * EN v1.0 Address: 0x8018CF58
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8018D2F4
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d2f4(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d378
 * EN v1.0 Address: 0x8018CF80
 * EN v1.0 Size: 228b
 * EN v1.1 Address: 0x8018D378
 * EN v1.1 Size: 248b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d378(undefined2 *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  param_1[3] = param_1[3] | 2;
  uVar2 = *(byte *)(param_2 + 0x19) ^ 0x80000000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a08);
  if ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a08) < FLOAT_803e49fc) {
    fVar1 = FLOAT_803e49fc;
  }
  fVar1 = fVar1 * FLOAT_803e4a00;
  *(float *)(param_1 + 4) = *(float *)(*(int *)(param_1 + 0x28) + 4) * fVar1;
  if (*(float **)(param_1 + 0x32) != (float *)0x0) {
    **(float **)(param_1 + 0x32) = **(float **)(param_1 + 0x28) * fVar1;
  }
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x18);
  *param_1 = (short)((*(byte *)(param_2 + 0x1a) & 0x3f) << 10);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  *(undefined4 *)(param_1 + 0x7a) = 0;
  *(undefined4 *)(param_1 + 0x7c) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d470
 * EN v1.0 Address: 0x8018D064
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8018D470
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d470(int param_1)
{
  uint *puVar1;
  
  puVar1 = *(uint **)(param_1 + 0xb8);
  (**(code **)(*DAT_803dd6f8 + 0x18))();
  if (*puVar1 != 0) {
    FUN_8001f448(*puVar1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d4bc
 * EN v1.0 Address: 0x8018D0B4
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8018D4BC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d4bc(int param_1)
{
  int iVar1;
  char in_r8;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    iVar1 = *piVar2;
    if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
      FUN_80060630(iVar1);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8018d520
 * EN v1.0 Address: 0x8018D110
 * EN v1.0 Size: 688b
 * EN v1.1 Address: 0x8018D520
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8018d520(void)
{
  bool bVar1;
  float fVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined4 uVar8;
  int *piVar9;
  undefined auStack_28 [4];
  float local_24;
  float local_20;
  float local_1c;
  
  uVar4 = FUN_80286840();
  piVar9 = *(int **)(uVar4 + 0xb8);
  FUN_8002bac4();
  iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
  if (iVar5 == 0) {
    if (*piVar9 != 0) {
      FUN_8001dc30((double)FLOAT_803e4a10,*piVar9,'\0');
    }
    FUN_80035ea4(uVar4);
    piVar9[1] = (int)((float)piVar9[1] - FLOAT_803dc074);
    if (FLOAT_803e4a14 < (float)piVar9[1]) {
      uVar7 = 0;
    }
    else {
      uVar7 = 3;
      piVar9[1] = (int)((float)piVar9[1] + FLOAT_803e4a18);
    }
    uVar8 = 0;
    uVar6 = 0;
    if (*(char *)((int)piVar9 + 0x12) != '\0') {
      FUN_8000dbb0();
      *(undefined *)((int)piVar9 + 0x12) = 0;
    }
  }
  else {
    if (*piVar9 != 0) {
      FUN_8001dc30((double)FLOAT_803e4a10,*piVar9,'\x01');
    }
    FUN_80035eec(uVar4,0x1f,1,0);
    piVar9[2] = (int)((float)piVar9[2] - FLOAT_803dc074);
    fVar2 = (float)piVar9[2];
    bVar1 = fVar2 <= FLOAT_803e4a14;
    if (bVar1) {
      piVar9[2] = (int)(fVar2 + FLOAT_803e4a10);
    }
    uVar6 = (uint)bVar1;
    uVar8 = 2;
    uVar7 = 0;
    if (*(char *)((int)piVar9 + 0x12) == '\0') {
      FUN_8000dcdc(uVar4,0x9e);
      *(undefined *)((int)piVar9 + 0x12) = 1;
    }
  }
  local_24 = FLOAT_803e4a14;
  local_20 = FLOAT_803e4a18;
  local_1c = FLOAT_803e4a14;
  FUN_80098da4(uVar4,uVar8,uVar7,uVar6,&local_24);
  iVar5 = *piVar9;
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    uVar4 = FUN_80022264(0xffffffe7,0x19);
    iVar5 = *piVar9;
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa) + (short)uVar4;
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xff < sVar3) {
      sVar3 = 0xff;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    *(char *)(*piVar9 + 0x2f9) = (char)sVar3;
  }
  FUN_8028688c();
  return;
}
