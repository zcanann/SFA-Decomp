// Function: FUN_80219a54
// Entry: 80219a54
// Size: 144 bytes

undefined4 FUN_80219a54(int param_1)

{
  int iVar1;
  
  FUN_8002bac4();
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_80014b68(0,0x100);
    iVar1 = (**(code **)(*DAT_803dd6e8 + 0x1c))();
    if (iVar1 == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    }
  }
  return 0;
}

