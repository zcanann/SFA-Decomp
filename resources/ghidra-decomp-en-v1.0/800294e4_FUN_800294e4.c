// Function: FUN_800294e4
// Entry: 800294e4
// Size: 140 bytes

int FUN_800294e4(byte *param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = countLeadingZeros(1 - (uint)*param_1);
  iVar2 = FUN_80025ae4(param_1,param_2,uVar1 >> 5,param_3);
  FUN_80024ec8(iVar2,*(undefined4 *)(iVar2 + 0x2c));
  if (*(int *)(iVar2 + 0x30) != 0) {
    FUN_80024ec8(iVar2);
  }
  FUN_80028ec0(param_1,iVar2);
  *(undefined4 *)(param_1 + 8) = 0;
  FUN_80241a1c(param_1,*(undefined4 *)(param_1 + 0xc));
  return iVar2;
}

