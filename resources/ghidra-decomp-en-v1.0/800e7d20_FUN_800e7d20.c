// Function: FUN_800e7d20
// Entry: 800e7d20
// Size: 120 bytes

void FUN_800e7d20(uint *param_1,undefined param_2,uint param_3,undefined param_4)

{
  FUN_800033a8(param_1,0,0x268);
  *(undefined *)((int)param_1 + 0x25b) = param_4;
  *param_1 = param_3 | 0x4000000;
  *(undefined *)((int)param_1 + 0x262) = param_2;
  *(undefined *)(param_1 + 0x96) = 5;
  return;
}

