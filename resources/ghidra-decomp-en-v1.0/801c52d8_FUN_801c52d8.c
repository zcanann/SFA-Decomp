// Function: FUN_801c52d8
// Entry: 801c52d8
// Size: 192 bytes

void FUN_801c52d8(undefined2 *param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c4b10;
  *(undefined2 *)(piVar2 + 7) = 10;
  *(undefined *)(piVar2 + 9) = 0;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *(short *)(piVar2 + 7) = *(short *)(param_2 + 0x1a) >> 8;
  }
  FUN_800200e8(299,0);
  FUN_800200e8(0x12d,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar2 == 0) {
    iVar1 = FUN_8001f4c8(0,1);
    *piVar2 = iVar1;
  }
  FUN_800200e8(0xf07,1);
  FUN_800200e8(0xefa,1);
  return;
}

