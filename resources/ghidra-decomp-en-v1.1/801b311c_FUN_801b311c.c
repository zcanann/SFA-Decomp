// Function: FUN_801b311c
// Entry: 801b311c
// Size: 100 bytes

void FUN_801b311c(int param_1)

{
  if (*(short *)(param_1 + 0x46) != 0x1d6) {
    (**(code **)(*DAT_803dd6e8 + 0x60))();
    FUN_80013e4c(DAT_803de7d0);
    DAT_803de7d0 = (undefined *)0x0;
  }
  FUN_8003709c(param_1,3);
  return;
}

