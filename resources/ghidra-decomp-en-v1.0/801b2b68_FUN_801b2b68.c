// Function: FUN_801b2b68
// Entry: 801b2b68
// Size: 100 bytes

void FUN_801b2b68(int param_1)

{
  if (*(short *)(param_1 + 0x46) != 0x1d6) {
    (**(code **)(*DAT_803dca68 + 0x60))();
    FUN_80013e2c(DAT_803ddb50);
    DAT_803ddb50 = 0;
  }
  FUN_80036fa4(param_1,3);
  return;
}

