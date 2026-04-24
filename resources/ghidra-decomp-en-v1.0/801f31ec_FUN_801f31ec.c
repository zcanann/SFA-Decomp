// Function: FUN_801f31ec
// Entry: 801f31ec
// Size: 448 bytes

void FUN_801f31ec(int param_1,int param_2)

{
  int iVar1;
  int *piVar2;
  undefined auStack40 [16];
  float local_18;
  undefined4 local_10;
  uint uStack12;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if ((int)*(short *)(param_2 + 0x1a) == 0) {
    *(float *)(iVar1 + 4) = FLOAT_803e5dec;
  }
  else {
    uStack12 = (int)*(short *)(param_2 + 0x1a) ^ 0x80000000;
    local_10 = 0x43300000;
    *(float *)(iVar1 + 4) = (float)((double)CONCAT44(0x43300000,uStack12) - DOUBLE_803e5e00);
  }
  if (*(short *)(param_2 + 0x1c) == 0) {
    *(undefined2 *)(iVar1 + 10) = 0x8c;
  }
  else {
    *(short *)(iVar1 + 10) = *(short *)(param_2 + 0x1c);
  }
  *(undefined *)(iVar1 + 0xc) = *(undefined *)(param_2 + 0x19);
  local_18 = FLOAT_803e5df0;
  if (*(char *)(iVar1 + 0xc) == '\0') {
    piVar2 = (int *)FUN_80013ec8(0x69,1);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e5df4;
    (**(code **)(*piVar2 + 4))(param_1,1,auStack40,0x10004,0xffffffff,0);
  }
  else if (*(char *)(iVar1 + 0xc) == '\x7f') {
    piVar2 = (int *)FUN_80013ec8(0x69,1);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e5df4;
    (**(code **)(*piVar2 + 4))(param_1,2,auStack40,0x10004,0xffffffff,0);
  }
  else {
    piVar2 = (int *)FUN_80013ec8(99,1);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e5df4;
    (**(code **)(*piVar2 + 4))(param_1,2,auStack40,0x10004,0xffffffff,0);
  }
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) * FLOAT_803e5df8;
  FUN_80013e2c(piVar2);
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

