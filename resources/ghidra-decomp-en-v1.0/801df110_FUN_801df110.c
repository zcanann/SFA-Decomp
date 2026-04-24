// Function: FUN_801df110
// Entry: 801df110
// Size: 220 bytes

uint FUN_801df110(int param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar5 = *(int *)(param_1 + 0xb8);
  uVar2 = FUN_8002b9ec();
  uVar3 = FUN_80014e70(0);
  if ((uVar3 & 0x100) == 0) {
    uVar3 = 0;
  }
  else {
    *(undefined *)(iVar5 + 2) = 0;
    iVar4 = FUN_8029689c(uVar2);
    bVar1 = iVar4 < *(short *)(iVar6 + 0x1a);
    if (bVar1) {
      *(undefined *)(iVar5 + 2) = 2;
    }
    else {
      *(undefined *)(iVar5 + 2) = 0;
    }
    uVar3 = (uint)!bVar1;
    if (param_3 == 0x15) {
      uVar3 = countLeadingZeros(uVar3);
      uVar3 = uVar3 >> 5;
    }
    else if ((param_3 < 0x15) && (0x13 < param_3)) {
      uVar3 = countLeadingZeros(1 - uVar3);
      uVar3 = uVar3 >> 5;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

