// Function: FUN_8003757c
// Entry: 8003757c
// Size: 104 bytes

undefined4 FUN_8003757c(int param_1,int *param_2,int *param_3,int *param_4)

{
  int *piVar1;
  
  if (param_1 == 0) {
    return 0;
  }
  piVar1 = *(int **)(param_1 + 0xdc);
  if ((piVar1 != (int *)0x0) && (*piVar1 != 0)) {
    if (param_2 != (int *)0x0) {
      *param_2 = piVar1[2];
    }
    if (param_3 != (int *)0x0) {
      *param_3 = piVar1[3];
    }
    if (param_4 != (int *)0x0) {
      *param_4 = piVar1[4];
    }
    return 1;
  }
  return 0;
}

