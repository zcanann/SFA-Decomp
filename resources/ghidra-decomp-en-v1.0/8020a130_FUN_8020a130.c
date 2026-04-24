// Function: FUN_8020a130
// Entry: 8020a130
// Size: 152 bytes

void FUN_8020a130(undefined2 *param_1,int param_2)

{
  int *piVar1;
  
  if (param_1 != (undefined2 *)0x0) {
    piVar1 = *(int **)(param_1 + 0x5c);
    if (*(short *)(param_2 + 0x1a) < 1) {
      *(undefined2 *)(param_2 + 0x1a) = 1;
    }
    if (*(short *)(param_2 + 0x1c) < 1) {
      *(undefined2 *)(param_2 + 0x1c) = 1;
    }
    *(code **)(param_1 + 0x5e) = FUN_80209f34;
    *piVar1 = (int)*(short *)(param_2 + 0x1a);
    piVar1[1] = (int)*(short *)(param_2 + 0x1c);
    piVar1[2] = (int)*(short *)(param_2 + 0x20);
    *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
    FUN_80035df4(param_1,0x13,1,0);
  }
  return;
}

