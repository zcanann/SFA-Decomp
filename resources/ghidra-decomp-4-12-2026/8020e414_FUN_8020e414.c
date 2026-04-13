// Function: FUN_8020e414
// Entry: 8020e414
// Size: 516 bytes

void FUN_8020e414(void)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  ushort uVar5;
  int iVar4;
  char in_r8;
  int *piVar6;
  
  iVar2 = FUN_8028683c();
  piVar6 = *(int **)(iVar2 + 0xb8);
  sVar1 = **(short **)(iVar2 + 0x4c);
  if (sVar1 == 0x5f5) {
    FUN_8003b9ec(iVar2);
  }
  else if ((in_r8 != '\0') && (sVar1 != 0x61e)) {
    if (sVar1 < 0x61e) {
      if (sVar1 == 0x5de) {
        if (*(char *)((int)piVar6 + 0x27d) == '\0') {
          FUN_8003b9ec(iVar2);
        }
        goto LAB_8020e604;
      }
      if ((0x5dd < sVar1) && (sVar1 == 0x5e3)) {
        uVar3 = FUN_80022264(0,0x19);
        if ((uVar3 != 0) && (*(char *)((int)piVar6 + 0x27d) != '\0')) {
          FUN_8025da88(0x1e0,0x32,0x82,0x96);
          FUN_8003b9ec(iVar2);
          FUN_8000f0d8();
        }
        goto LAB_8020e604;
      }
    }
    else {
      if (sVar1 == 0x80f) {
        if ((*piVar6 != 0) && (iVar4 = FUN_8001dc28(*piVar6), iVar4 != 0)) {
          FUN_80060630(*piVar6);
        }
        FUN_8003b9ec(iVar2);
        goto LAB_8020e604;
      }
      if ((sVar1 < 0x80f) && (sVar1 == 0x740)) {
        if ((*(char *)((int)piVar6 + 0x27d) == '\0') ||
           ((uVar5 = FUN_8012e0e8(), (uVar5 & 0xff) != 0 ||
            (iVar4 = (**(code **)(*DAT_803dd6cc + 0x14))(), iVar4 == 0)))) {
          DAT_803de9b4 = 2;
        }
        else if (DAT_803de9b4 == 0) {
          FUN_8003b9ec(iVar2);
        }
        else {
          DAT_803de9b4 = DAT_803de9b4 + -1;
        }
        goto LAB_8020e604;
      }
    }
    FUN_8003b9ec(iVar2);
  }
LAB_8020e604:
  FUN_80286888();
  return;
}

