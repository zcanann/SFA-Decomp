// Function: FUN_801fe260
// Entry: 801fe260
// Size: 340 bytes

void FUN_801fe260(int param_1)

{
  uint uVar1;
  float *pfVar2;
  int iVar3;
  undefined8 local_18;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  pfVar2 = *(float **)(param_1 + 0xb8);
  *(float *)(param_1 + 0x10) = FLOAT_803dc074 * *pfVar2 + *(float *)(param_1 + 0x10);
  if (FLOAT_803e6e48 + *(float *)(iVar3 + 0xc) < *(float *)(param_1 + 0x10)) {
    uVar1 = FUN_80022264(5,0x14);
    local_18 = (double)CONCAT44(0x43300000,uVar1 ^ 0x80000000);
    *pfVar2 = FLOAT_803e6e4c * (float)(local_18 - DOUBLE_803e6e50);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar3 + 0xc);
  }
  *(short *)((int)pfVar2 + 0xe) = *(short *)((int)pfVar2 + 0xe) + (short)(int)FLOAT_803dc074;
  if ((DAT_803de958 != (int *)0x0) && (0x27 < *(short *)((int)pfVar2 + 0xe))) {
    (**(code **)(*DAT_803de958 + 4))(param_1,0,0,4,0xffffffff,0);
    *(undefined2 *)((int)pfVar2 + 0xe) = 0;
  }
  if (*(char *)(pfVar2 + 4) == '\0') {
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x3a4,0,2,0xffffffff,0);
  }
  *(byte *)(pfVar2 + 4) = *(byte *)(pfVar2 + 4) ^ 1;
  return;
}

