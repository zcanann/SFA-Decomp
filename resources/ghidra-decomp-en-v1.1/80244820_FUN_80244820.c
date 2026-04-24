// Function: FUN_80244820
// Entry: 80244820
// Size: 220 bytes

undefined4 FUN_80244820(int *param_1,undefined4 *param_2,uint param_3)

{
  FUN_80243e74();
  while( true ) {
    if (param_1[7] != 0) {
      if (param_2 != (undefined4 *)0x0) {
        *param_2 = *(undefined4 *)(param_1[4] + param_1[6] * 4);
      }
      param_1[6] = (param_1[6] + 1) - ((param_1[6] + 1) / param_1[5]) * param_1[5];
      param_1[7] = param_1[7] + -1;
      FUN_802472b0(param_1);
      FUN_80243e9c();
      return 1;
    }
    if ((param_3 & 1) == 0) break;
    FUN_802471c4(param_1 + 2);
  }
  FUN_80243e9c();
  return 0;
}

