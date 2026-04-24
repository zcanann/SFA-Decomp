// Function: FUN_8018efe0
// Entry: 8018efe0
// Size: 352 bytes

void FUN_8018efe0(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined2 uVar2;
  float *pfVar3;
  
  *param_1 = 0;
  *(code **)(param_1 + 0x5e) = FUN_8018eaa4;
  pfVar3 = *(float **)(param_1 + 0x5c);
  *pfVar3 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e3e58);
  *(short *)(pfVar3 + 2) = (short)*(char *)(param_2 + 0x19);
  *(undefined2 *)((int)pfVar3 + 10) = *(undefined2 *)(param_2 + 0x1a);
  *(undefined2 *)((int)pfVar3 + 0xe) = *(undefined2 *)(param_2 + 0x1c);
  *(float *)(param_1 + 4) = FLOAT_803e3e50;
  *(undefined2 *)(pfVar3 + 5) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)((int)pfVar3 + 0x16) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar3 + 6) = 0;
  if (*(short *)((int)pfVar3 + 0xe) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)((int)pfVar3 + 0xe);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  if ((*(short *)((int)pfVar3 + 0x16) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    *(undefined2 *)(pfVar3 + 6) = 1;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x24) << 8);
  param_1[1] = (short)((int)*(char *)(param_2 + 0x23) << 8);
  param_1[2] = (short)((int)*(char *)(param_2 + 0x22) << 8);
  *(ushort *)((int)pfVar3 + 0x1a) = (ushort)*(byte *)(param_2 + 0x29) * 100;
  pfVar3[1] = *(float *)(param_1 + 6);
  uVar2 = FUN_800221a0(0,10);
  *(undefined2 *)((int)pfVar3 + 0x12) = uVar2;
  *(undefined2 *)(pfVar3 + 3) = 0;
  return;
}

