// Function: FUN_801ed02c
// Entry: 801ed02c
// Size: 104 bytes

uint FUN_801ed02c(int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (**(code **)(*DAT_803dd6ec + 0x34))(*(int *)(param_1 + 0xb8) + 0x28);
  if ((iVar1 == 3) && (DAT_803dcd24 == -1)) {
    uVar2 = 1;
  }
  else {
    uVar2 = countLeadingZeros((DAT_803dcd24 + -1) - iVar1);
    uVar2 = uVar2 >> 5;
  }
  return uVar2;
}

