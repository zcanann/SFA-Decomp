// Function: FUN_8004b11c
// Entry: 8004b11c
// Size: 376 bytes

void FUN_8004b11c(undefined4 param_1,undefined4 param_2,undefined param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  undefined8 uVar11;
  
  uVar11 = FUN_80286834();
  iVar3 = (int)((ulonglong)uVar11 >> 0x20);
  piVar6 = (int *)uVar11;
  iVar8 = *piVar6;
  if (*(char *)(iVar3 + 0x28) == '\0') {
    uVar2 = ~(int)*(char *)(iVar8 + 0x1b);
  }
  else {
    uVar2 = (uint)*(char *)(iVar8 + 0x1b);
  }
  iVar7 = 0;
  iVar9 = iVar8;
  do {
    iVar1 = DAT_803dd988;
    if ((((-1 < *(int *)(iVar9 + 0x1c)) && ((uVar2 & 0xff & 1 << iVar7) != 0)) &&
        (iVar4 = (**(code **)(*DAT_803dd71c + 0x1c))(), iVar1 = DAT_803dd988, iVar4 != 0)) &&
       (iVar1 = iVar4, *(char *)(iVar4 + 0x19) == '$')) {
      FUN_80020078(0x4e2);
      if (((((int)*(short *)(iVar4 + 0x30) == 0xffffffff) ||
           (uVar5 = FUN_80020078((int)*(short *)(iVar4 + 0x30)), iVar1 = DAT_803dd988, uVar5 != 0))
          && (((int)*(short *)(iVar4 + 0x32) == 0xffffffff ||
              (uVar5 = FUN_80020078((int)*(short *)(iVar4 + 0x32)), iVar1 = DAT_803dd988, uVar5 == 0
              )))) &&
         ((*(char *)(iVar4 + 0x1a) != '\b' ||
          (iVar1 = DAT_803dd988, *(char *)(iVar8 + 0x1a) != '\t')))) {
        dVar10 = FUN_80021794((float *)(iVar8 + 8),(float *)(iVar4 + 8));
        uVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,piVar6[2])
                                                            - DOUBLE_803df728) + dVar10));
        FUN_8004acd8(iVar3,piVar6,param_3,uVar5,iVar4);
        iVar1 = DAT_803dd988;
      }
    }
    DAT_803dd988 = iVar1;
    iVar9 = iVar9 + 4;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
  FUN_80286880();
  return;
}

