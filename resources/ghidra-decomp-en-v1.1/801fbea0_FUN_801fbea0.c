// Function: FUN_801fbea0
// Entry: 801fbea0
// Size: 316 bytes

void FUN_801fbea0(undefined2 *param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  *(undefined **)(param_1 + 0x5e) = &LAB_801fb858;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)((int)pfVar2 + 10) = 0;
  *(undefined2 *)(pfVar2 + 3) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)((int)pfVar2 + 0xe) = *(undefined2 *)(param_2 + 0x1e);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e6d90);
  *(char *)((int)pfVar2 + 0x1a) = (char)*(undefined2 *)(param_2 + 0x1c);
  *(undefined2 *)((int)pfVar2 + 0x12) = 0;
  *(undefined2 *)(pfVar2 + 5) = 0;
  *(undefined2 *)((int)pfVar2 + 0x16) = 0;
  *(undefined2 *)(pfVar2 + 6) = 0;
  if (param_1[0x23] == 0x3bf) {
    uVar1 = FUN_80020078((int)*(short *)((int)pfVar2 + 0xe));
    if (uVar1 == 0) {
      *(undefined2 *)((int)pfVar2 + 10) = 3;
    }
    else {
      *(undefined2 *)((int)pfVar2 + 10) = 4;
      *(byte *)(pfVar2 + 7) = *(byte *)(pfVar2 + 7) & 0x7f | 0x80;
    }
  }
  if ((param_1[0x23] == 0x3b7) && (uVar1 = FUN_80020078(0x4ee), uVar1 != 0)) {
    uVar1 = FUN_80020078((int)*(short *)((int)pfVar2 + 0xe));
    if (uVar1 == 0) {
      *(undefined2 *)((int)pfVar2 + 10) = 4;
      *(byte *)(pfVar2 + 7) = *(byte *)(pfVar2 + 7) & 0x7f | 0x80;
    }
    else {
      *(undefined2 *)((int)pfVar2 + 10) = 3;
    }
  }
  return;
}

