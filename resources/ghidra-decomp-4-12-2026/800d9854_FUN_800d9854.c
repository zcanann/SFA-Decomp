// Function: FUN_800d9854
// Entry: 800d9854
// Size: 160 bytes

void FUN_800d9854(int param_1,int param_2,int param_3)

{
  if (*(short *)(param_2 + 0x274) != param_3) {
    *(short *)(param_2 + 0x276) = *(short *)(param_2 + 0x274);
    *(short *)(param_2 + 0x274) = (short)param_3;
    if (*(code **)(param_2 + 0x304) != (code *)0x0) {
      (**(code **)(param_2 + 0x304))();
      *(undefined4 *)(param_2 + 0x304) = 0;
    }
    *(undefined4 *)(param_2 + 0x304) = *(undefined4 *)(param_2 + 0x308);
  }
  *(undefined2 *)(param_2 + 0x338) = 0;
  *(undefined *)(param_2 + 0x27a) = 1;
  *(undefined *)(param_2 + 0x34d) = 0;
  *(undefined *)(param_2 + 0x34c) = 0;
  *(undefined *)(param_2 + 0x356) = 0;
  *(undefined2 *)(param_2 + 0x278) = 0;
  if (*(int *)(param_1 + 0x54) != 0) {
    *(undefined *)(*(int *)(param_1 + 0x54) + 0x70) = 0;
  }
  return;
}

