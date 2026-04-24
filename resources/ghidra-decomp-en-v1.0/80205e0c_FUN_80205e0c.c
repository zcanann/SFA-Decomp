// Function: FUN_80205e0c
// Entry: 80205e0c
// Size: 300 bytes

void FUN_80205e0c(undefined2 *param_1,int param_2)

{
  int *piVar1;
  int *piVar2;
  undefined auStack56 [16];
  float local_28;
  undefined4 local_20;
  uint uStack28;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  *param_1 = (short)(((int)*(char *)(param_2 + 0x18) & 0x3fU) << 10);
  if (*(short *)(param_2 + 0x1a) < 1) {
    *(float *)(param_1 + 4) = FLOAT_803e63e8;
  }
  else {
    uStack28 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_20 = 0x43300000;
    *(float *)(param_1 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e63f0) / FLOAT_803e63e4;
  }
  *(undefined *)((int)piVar2 + 9) = *(undefined *)(param_2 + 0x19);
  *piVar2 = (int)*(short *)(param_2 + 0x1e);
  local_28 = FLOAT_803e63e0;
  if (*(char *)((int)piVar2 + 9) == '\0') {
    *(undefined *)((int)piVar2 + 10) = 1;
    piVar1 = (int *)FUN_80013ec8(0x69,1);
    if (*(short *)(param_2 + 0x1c) == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,auStack56,0x10004,0xffffffff,0);
    }
  }
  *(char *)((int)piVar2 + 0xd) = (char)*(undefined2 *)(param_2 + 0x1c);
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

