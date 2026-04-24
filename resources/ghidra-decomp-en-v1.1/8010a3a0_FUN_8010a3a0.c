// Function: FUN_8010a3a0
// Entry: 8010a3a0
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x8010a6f8) */
/* WARNING: Removing unreachable block (ram,0x8010a6f0) */
/* WARNING: Removing unreachable block (ram,0x8010a6e8) */
/* WARNING: Removing unreachable block (ram,0x8010a6e0) */
/* WARNING: Removing unreachable block (ram,0x8010a3c8) */
/* WARNING: Removing unreachable block (ram,0x8010a3c0) */
/* WARNING: Removing unreachable block (ram,0x8010a3b8) */
/* WARNING: Removing unreachable block (ram,0x8010a3b0) */

void FUN_8010a3a0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int *piVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double extraout_f1;
  undefined8 extraout_f1_00;
  double dVar10;
  double in_f28;
  double dVar11;
  double in_f29;
  double in_f30;
  double dVar12;
  double in_f31;
  double dVar13;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  undefined auStack_78 [4];
  int local_74;
  int local_70 [2];
  int local_68;
  int local_64;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar14 = FUN_8028683c();
  piVar2 = (int *)((ulonglong)uVar14 >> 0x20);
  puVar6 = (undefined4 *)uVar14;
  dVar11 = extraout_f1;
  uVar14 = param_2;
  dVar12 = param_3;
  iVar3 = (**(code **)(*DAT_803dd71c + 0x1c))(*piVar2);
  bVar1 = true;
  for (iVar8 = 0; iVar8 < 5; iVar8 = iVar8 + 1) {
    if ((((-1 < *(int *)(iVar3 + iVar8 * 4 + 0x1c)) &&
         (((int)*(char *)(iVar3 + 0x1b) & 1 << iVar8) == 0)) &&
        (iVar9 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar9 != 0)) &&
       (((*(byte *)(iVar9 + 0x31) == param_11 || (*(byte *)(iVar9 + 0x32) == param_11)) ||
        (*(byte *)(iVar9 + 0x33) == param_11)))) {
      bVar1 = false;
      iVar8 = 5;
    }
  }
  if (bVar1) {
    for (iVar8 = 0; iVar8 < 5; iVar8 = iVar8 + 1) {
      iVar9 = iVar8 * 4 + 0x1c;
      if (((-1 < *(int *)(iVar3 + iVar9)) && (((int)*(char *)(iVar3 + 0x1b) & 1 << iVar8) != 0)) &&
         ((iVar7 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar7 != 0 &&
          (((*(byte *)(iVar7 + 0x31) == param_11 || (*(byte *)(iVar7 + 0x32) == param_11)) ||
           (*(byte *)(iVar7 + 0x33) == param_11)))))) {
        *piVar2 = *(int *)(iVar3 + iVar9);
        iVar8 = 5;
      }
    }
  }
  bVar1 = false;
  dVar13 = (double)FLOAT_803e2508;
  while (!bVar1) {
    bVar1 = true;
    uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(*piVar2);
    FUN_8010acf0(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar4,
                 local_70,param_11,param_12,param_13,param_14,param_15,param_16);
    param_3 = dVar12;
    param_2 = uVar14;
    uVar14 = param_2;
    dVar12 = param_3;
    dVar10 = FUN_8010aee4(dVar11,param_2,param_3,local_70);
    if (dVar13 <= dVar10) {
      if ((((double)FLOAT_803e250c < dVar10) && (-1 < local_68)) && (-1 < local_64)) {
        *piVar2 = local_68;
        bVar1 = false;
      }
    }
    else if (-1 < local_70[0]) {
      *piVar2 = local_70[0];
      bVar1 = false;
    }
  }
  uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(*piVar2);
  FUN_8010a718(uVar4,&local_74,param_11);
  uVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar6);
  iVar3 = FUN_8010a718(uVar4,auStack_78,param_11);
  *puVar6 = *(undefined4 *)(iVar3 + 0x14);
  for (iVar3 = 0; iVar3 < local_74; iVar3 = iVar3 + 1) {
    iVar8 = (**(code **)(*DAT_803dd71c + 0x1c))(*puVar6);
    for (iVar9 = 0; iVar9 < 5; iVar9 = iVar9 + 1) {
      iVar7 = iVar9 * 4 + 0x1c;
      if (((-1 < *(int *)(iVar8 + iVar7)) && (((int)*(char *)(iVar8 + 0x1b) & 1 << iVar9) == 0)) &&
         ((iVar5 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar5 != 0 &&
          (((*(byte *)(iVar5 + 0x31) == param_11 || (*(byte *)(iVar5 + 0x32) == param_11)) ||
           (*(byte *)(iVar5 + 0x33) == param_11)))))) {
        *puVar6 = *(undefined4 *)(iVar8 + iVar7);
        iVar9 = 5;
      }
    }
  }
  FUN_80286888();
  return;
}

