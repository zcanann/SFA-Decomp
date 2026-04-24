// Function: FUN_8001e608
// Entry: 8001e608
// Size: 44 bytes

void FUN_8001e608(int param_1,undefined4 param_2,undefined4 param_3)

{
  (&DAT_8033be68)[param_1 * 4] = param_2;
  (&DAT_8033be64)[param_1 * 4] = 0;
  (&DAT_8033be6c)[param_1 * 4] = param_3;
  (&DAT_8033be60)[param_1 * 0x10] = 1;
  return;
}

