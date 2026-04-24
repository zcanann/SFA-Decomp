// Function: FUN_8004afa0
// Entry: 8004afa0
// Size: 376 bytes

void FUN_8004afa0(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860d0();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  piVar7 = (int *)uVar12;
  iVar9 = *piVar7;
  if (*(char *)(iVar3 + 0x28) == '\0') {
    uVar2 = ~(int)*(char *)(iVar9 + 0x1b);
  }
  else {
    uVar2 = (uint)*(char *)(iVar9 + 0x1b);
  }
  iVar8 = 0;
  iVar10 = iVar9;
  do {
    iVar1 = DAT_803dcd08;
    if ((((((-1 < *(int *)(iVar10 + 0x1c)) && ((uVar2 & 0xff & 1 << iVar8) != 0)) &&
          (iVar4 = (**(code **)(*DAT_803dca9c + 0x1c))(), iVar1 = DAT_803dcd08, iVar4 != 0)) &&
         (iVar1 = iVar4, *(char *)(iVar4 + 0x19) == '$')) &&
        (((FUN_8001ffb4(0x4e2), *(short *)(iVar4 + 0x30) == -1 ||
          (iVar5 = FUN_8001ffb4(), iVar1 = DAT_803dcd08, iVar5 != 0)) &&
         ((*(short *)(iVar4 + 0x32) == -1 ||
          (iVar5 = FUN_8001ffb4(), iVar1 = DAT_803dcd08, iVar5 == 0)))))) &&
       ((*(char *)(iVar4 + 0x1a) != '\b' || (iVar1 = DAT_803dcd08, *(char *)(iVar9 + 0x1a) != '\t'))
       )) {
      dVar11 = (double)FUN_800216d0(iVar9 + 8,iVar4 + 8);
      uVar6 = FUN_80285fb4((double)(float)((double)(float)((double)CONCAT44(0x43300000,piVar7[2]) -
                                                          DOUBLE_803deaa8) + dVar11));
      FUN_8004ab5c(iVar3,piVar7,param_3,uVar6,iVar4);
      iVar1 = DAT_803dcd08;
    }
    DAT_803dcd08 = iVar1;
    iVar10 = iVar10 + 4;
    iVar8 = iVar8 + 1;
  } while (iVar8 < 4);
  FUN_8028611c();
  return;
}

