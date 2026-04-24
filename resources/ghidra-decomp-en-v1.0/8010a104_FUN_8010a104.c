// Function: FUN_8010a104
// Entry: 8010a104
// Size: 888 bytes

/* WARNING: Removing unreachable block (ram,0x8010a454) */
/* WARNING: Removing unreachable block (ram,0x8010a444) */
/* WARNING: Removing unreachable block (ram,0x8010a44c) */
/* WARNING: Removing unreachable block (ram,0x8010a45c) */

void FUN_8010a104(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)

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
  undefined4 uVar10;
  undefined8 extraout_f1;
  double dVar11;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined auStack120 [4];
  int local_74;
  int local_70 [2];
  int local_68;
  int local_64;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar13 = FUN_802860d8();
  piVar2 = (int *)((ulonglong)uVar13 >> 0x20);
  puVar6 = (undefined4 *)uVar13;
  uVar13 = extraout_f1;
  iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(*piVar2);
  bVar1 = true;
  for (iVar8 = 0; iVar8 < 5; iVar8 = iVar8 + 1) {
    if ((((-1 < *(int *)(iVar3 + iVar8 * 4 + 0x1c)) &&
         (((int)*(char *)(iVar3 + 0x1b) & 1 << iVar8) == 0)) &&
        (iVar9 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar9 != 0)) &&
       (((*(byte *)(iVar9 + 0x31) == param_6 || (*(byte *)(iVar9 + 0x32) == param_6)) ||
        (*(byte *)(iVar9 + 0x33) == param_6)))) {
      bVar1 = false;
      iVar8 = 5;
    }
  }
  if (bVar1) {
    for (iVar8 = 0; iVar8 < 5; iVar8 = iVar8 + 1) {
      iVar9 = iVar8 * 4 + 0x1c;
      if (((-1 < *(int *)(iVar3 + iVar9)) && (((int)*(char *)(iVar3 + 0x1b) & 1 << iVar8) != 0)) &&
         ((iVar7 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar7 != 0 &&
          (((*(byte *)(iVar7 + 0x31) == param_6 || (*(byte *)(iVar7 + 0x32) == param_6)) ||
           (*(byte *)(iVar7 + 0x33) == param_6)))))) {
        *piVar2 = *(int *)(iVar3 + iVar9);
        iVar8 = 5;
      }
    }
  }
  bVar1 = false;
  dVar12 = (double)FLOAT_803e1888;
  while (!bVar1) {
    bVar1 = true;
    uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(*piVar2);
    FUN_8010aa54(uVar4,local_70,param_6);
    dVar11 = (double)FUN_8010ac48(uVar13,param_2,param_3,local_70);
    if (dVar12 <= dVar11) {
      if ((((double)FLOAT_803e188c < dVar11) && (-1 < local_68)) && (-1 < local_64)) {
        *piVar2 = local_68;
        bVar1 = false;
      }
    }
    else if (-1 < local_70[0]) {
      *piVar2 = local_70[0];
      bVar1 = false;
    }
  }
  uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(*piVar2);
  FUN_8010a47c(uVar4,&local_74,param_6);
  uVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar6);
  iVar3 = FUN_8010a47c(uVar4,auStack120,param_6);
  *puVar6 = *(undefined4 *)(iVar3 + 0x14);
  for (iVar3 = 0; iVar3 < local_74; iVar3 = iVar3 + 1) {
    iVar8 = (**(code **)(*DAT_803dca9c + 0x1c))(*puVar6);
    for (iVar9 = 0; iVar9 < 5; iVar9 = iVar9 + 1) {
      iVar7 = iVar9 * 4 + 0x1c;
      if (((-1 < *(int *)(iVar8 + iVar7)) && (((int)*(char *)(iVar8 + 0x1b) & 1 << iVar9) == 0)) &&
         ((iVar5 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar5 != 0 &&
          (((*(byte *)(iVar5 + 0x31) == param_6 || (*(byte *)(iVar5 + 0x32) == param_6)) ||
           (*(byte *)(iVar5 + 0x33) == param_6)))))) {
        *puVar6 = *(undefined4 *)(iVar8 + iVar7);
        iVar9 = 5;
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  FUN_80286124();
  return;
}

