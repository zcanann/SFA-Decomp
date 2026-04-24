// Function: FUN_8018f55c
// Entry: 8018f55c
// Size: 352 bytes

void FUN_8018f55c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_8018f020;
  pfVar2 = *(float **)(param_1 + 0x5c);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e4af0);
  *(short *)(pfVar2 + 2) = (short)*(char *)(param_2 + 0x19);
  *(undefined2 *)((int)pfVar2 + 10) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)((int)pfVar2 + 0xe) = *(undefined2 *)(param_2 + 0x1c);
  *(float *)(param_1 + 4) = FLOAT_803e4ae8;
  *(undefined2 *)(pfVar2 + 5) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)((int)pfVar2 + 0x16) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar2 + 6) = 0;
  if (*(short *)((int)pfVar2 + 0xe) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)((int)pfVar2 + 0xe);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  if (((int)*(short *)((int)pfVar2 + 0x16) != 0xffffffff) &&
     (uVar1 = FUN_80020078((int)*(short *)((int)pfVar2 + 0x16)), uVar1 != 0)) {
    *(undefined2 *)(pfVar2 + 6) = 1;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x24) << 8);
  param_1[1] = (short)((int)*(char *)(param_2 + 0x23) << 8);
  param_1[2] = (short)((int)*(char *)(param_2 + 0x22) << 8);
  *(ushort *)((int)pfVar2 + 0x1a) = (ushort)*(byte *)(param_2 + 0x29) * 100;
  pfVar2[1] = *(float *)(param_1 + 6);
  uVar1 = FUN_80022264(0,10);
  *(short *)((int)pfVar2 + 0x12) = (short)uVar1;
  *(undefined2 *)(pfVar2 + 3) = 0;
  return;
}

