// Function: FUN_801df700
// Entry: 801df700
// Size: 220 bytes

uint FUN_801df700(int param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0x4c);
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar2 = FUN_8002bac4();
  uVar3 = FUN_80014e9c(0);
  if ((uVar3 & 0x100) == 0) {
    uVar3 = 0;
  }
  else {
    *(undefined *)(iVar4 + 2) = 0;
    iVar2 = FUN_80296ffc(iVar2);
    bVar1 = iVar2 < *(short *)(iVar5 + 0x1a);
    if (bVar1) {
      *(undefined *)(iVar4 + 2) = 2;
    }
    else {
      *(undefined *)(iVar4 + 2) = 0;
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

