// Function: FUN_801886d4
// Entry: 801886d4
// Size: 200 bytes

void FUN_801886d4(undefined2 *param_1,int param_2)

{
  uint uVar1;
  float *pfVar2;
  
  pfVar2 = *(float **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(undefined2 *)((int)pfVar2 + 6) = *(undefined2 *)(param_2 + 0x20);
  *(undefined2 *)(pfVar2 + 1) = *(undefined2 *)(param_2 + 0x1e);
  *pfVar2 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e47f8);
  param_1[0x58] = param_1[0x58] | 0x6000;
  *(undefined **)(param_1 + 0x5e) = &LAB_80188488;
  *(float *)(param_1 + 8) = *(float *)(param_2 + 0xc) + *pfVar2;
  FUN_8002b95c((int)param_1,(int)*(char *)(param_2 + 0x19));
  *(undefined *)(pfVar2 + 2) = 0;
  uVar1 = FUN_80020078((int)*(short *)((int)pfVar2 + 6));
  if (uVar1 == 0) {
    *(undefined *)((int)pfVar2 + 9) = 1;
  }
  return;
}

