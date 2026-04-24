// Function: FUN_801ec9f4
// Entry: 801ec9f4
// Size: 104 bytes

uint FUN_801ec9f4(int param_1)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = (**(code **)(*DAT_803dca6c + 0x34))(*(int *)(param_1 + 0xb8) + 0x28);
  if ((iVar1 == 3) && (DAT_803dc0bc == -1)) {
    uVar2 = 1;
  }
  else {
    uVar2 = countLeadingZeros((DAT_803dc0bc + -1) - iVar1);
    uVar2 = uVar2 >> 5;
  }
  return uVar2;
}

