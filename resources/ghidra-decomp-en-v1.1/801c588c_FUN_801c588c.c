// Function: FUN_801c588c
// Entry: 801c588c
// Size: 192 bytes

void FUN_801c588c(undefined2 *param_1,int param_2)

{
  int *piVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_801c50c4;
  *(undefined2 *)(piVar2 + 7) = 10;
  *(undefined *)(piVar2 + 9) = 0;
  if (0 < *(short *)(param_2 + 0x1a)) {
    *(short *)(piVar2 + 7) = *(short *)(param_2 + 0x1a) >> 8;
  }
  FUN_800201ac(299,0);
  FUN_800201ac(0x12d,0);
  *(undefined4 *)(param_1 + 0x7a) = 1;
  if (*piVar2 == 0) {
    piVar1 = FUN_8001f58c(0,'\x01');
    *piVar2 = (int)piVar1;
  }
  FUN_800201ac(0xf07,1);
  FUN_800201ac(0xefa,1);
  return;
}

