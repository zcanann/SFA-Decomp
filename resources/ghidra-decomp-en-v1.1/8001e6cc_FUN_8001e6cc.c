// Function: FUN_8001e6cc
// Entry: 8001e6cc
// Size: 44 bytes

void FUN_8001e6cc(int param_1,undefined4 param_2,undefined4 param_3)

{
  (&DAT_8033cac8)[param_1 * 4] = param_2;
  (&DAT_8033cac4)[param_1 * 4] = 0;
  (&DAT_8033cacc)[param_1 * 4] = param_3;
  (&DAT_8033cac0)[param_1 * 0x10] = 1;
  return;
}

