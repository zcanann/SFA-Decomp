// Function: FUN_80188998
// Entry: 80188998
// Size: 100 bytes

void FUN_80188998(int param_1)

{
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_80014b68(0,0x100);
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  return;
}

