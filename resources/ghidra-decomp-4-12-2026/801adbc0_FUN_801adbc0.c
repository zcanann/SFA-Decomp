// Function: FUN_801adbc0
// Entry: 801adbc0
// Size: 120 bytes

void FUN_801adbc0(undefined2 *param_1)

{
  if ((param_1[0x23] != 0x172) && (*(int *)(param_1 + 0x7a) == 0)) {
    *param_1 = 0;
    param_1[1] = 0;
    param_1[2] = 0;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

