// Function: FUN_80188440
// Entry: 80188440
// Size: 100 bytes

void FUN_80188440(int param_1)

{
  if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
    FUN_80014b3c(0,0x100);
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
  }
  return;
}

