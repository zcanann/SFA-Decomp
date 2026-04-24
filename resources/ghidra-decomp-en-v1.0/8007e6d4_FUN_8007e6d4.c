// Function: FUN_8007e6d4
// Entry: 8007e6d4
// Size: 116 bytes

void FUN_8007e6d4(uint param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  
  FUN_80003494(DAT_803dd044 + (param_1 & 0xff) * 0x6ec + 0xa50,param_3,0x6ec);
  FUN_80003494(DAT_803dd044 + 0x1f14,param_4,0xe4);
  iVar1 = FUN_8007e7c0(2);
  if (iVar1 == 0) {
    FUN_8007e7c0(1);
  }
  return;
}

