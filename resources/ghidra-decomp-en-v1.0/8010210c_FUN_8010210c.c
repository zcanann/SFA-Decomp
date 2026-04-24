// Function: FUN_8010210c
// Entry: 8010210c
// Size: 152 bytes

void FUN_8010210c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = FUN_80134be8();
  if (iVar2 == 0) {
    DAT_803db990 = 0xffff;
    uVar1 = countLeadingZeros(0x49 - DAT_803dd518);
    FUN_80100aa4(*(undefined4 *)(DAT_803dd524 + 0x128),uVar1 >> 5,param_1,param_2,param_3,param_4);
    *(undefined4 *)(DAT_803dd524 + 0x120) = 0;
  }
  return;
}

