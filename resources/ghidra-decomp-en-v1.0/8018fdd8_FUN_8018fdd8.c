// Function: FUN_8018fdd8
// Entry: 8018fdd8
// Size: 328 bytes

void FUN_8018fdd8(undefined2 *param_1,int param_2)

{
  undefined2 uVar1;
  int iVar2;
  float *pfVar3;
  
  *(code **)(param_1 + 0x5e) = FUN_8018fb84;
  pfVar3 = *(float **)(param_1 + 0x5c);
  *pfVar3 = (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x18) << 2 ^ 0x80000000) -
                   DOUBLE_803e3e60);
  *(undefined *)(pfVar3 + 2) = *(undefined *)(param_2 + 0x1f);
  *(undefined2 *)((int)pfVar3 + 10) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x22);
  *(undefined2 *)((int)pfVar3 + 0xe) = *(undefined2 *)(param_2 + 0x24);
  *(undefined2 *)(pfVar3 + 4) = *(undefined2 *)(param_2 + 0x26);
  *(undefined2 *)((int)pfVar3 + 0x12) = 0;
  *(ushort *)(pfVar3 + 5) = (ushort)*(byte *)(param_2 + 0x1c) << 2;
  *(ushort *)((int)pfVar3 + 0x16) = (ushort)*(byte *)(param_2 + 0x1d) << 2;
  *(ushort *)(pfVar3 + 6) = (ushort)*(byte *)(param_2 + 0x1e) << 2;
  uVar1 = (undefined2)((int)*(char *)(param_2 + 0x19) << 8);
  *(undefined2 *)((int)pfVar3 + 0x1e) = uVar1;
  param_1[2] = uVar1;
  uVar1 = (undefined2)((int)*(char *)(param_2 + 0x1a) << 8);
  *(undefined2 *)(pfVar3 + 7) = uVar1;
  param_1[1] = uVar1;
  uVar1 = (undefined2)((int)*(char *)(param_2 + 0x1b) << 8);
  *(undefined2 *)((int)pfVar3 + 0x1a) = uVar1;
  *param_1 = uVar1;
  *(float *)(param_1 + 4) = FLOAT_803e3e70;
  if (*(short *)(pfVar3 + 3) < 1) {
    *(int *)(param_1 + 0x7a) = (int)*(short *)(pfVar3 + 3);
  }
  else {
    *(undefined4 *)(param_1 + 0x7a) = 0;
  }
  if ((*(short *)(pfVar3 + 4) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
    *(undefined2 *)((int)pfVar3 + 0x12) = 1;
  }
  return;
}

