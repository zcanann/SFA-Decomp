// Function: FUN_80204650
// Entry: 80204650
// Size: 120 bytes

void FUN_80204650(undefined2 *param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = *(int **)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,0x1e);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_802043d8;
  *piVar1 = (int)*(short *)(param_2 + 0x1a);
  piVar1[1] = (int)*(short *)(param_2 + 0x1c);
  return;
}

