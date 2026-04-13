// Function: FUN_801f6a04
// Entry: 801f6a04
// Size: 376 bytes

void FUN_801f6a04(undefined2 *param_1,int param_2)

{
  undefined uVar2;
  uint uVar1;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801f5cc8;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = (short)((int)*(short *)(param_2 + 0x1a) << 8);
  *pfVar3 = ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                    DOUBLE_803e6ba0) / FLOAT_803e6b90) / FLOAT_803e6b94;
  pfVar3[1] = 0.0;
  *(undefined2 *)(pfVar3 + 2) = 0;
  *(undefined2 *)((int)pfVar3 + 10) = 0;
  *(undefined2 *)((int)pfVar3 + 0xe) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x20);
  *(short *)(pfVar3 + 4) = (short)*(char *)(param_2 + 0x19);
  *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) & 0x7f;
  param_1[0x58] = param_1[0x58] | 0x6000;
  uVar2 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56));
  *(undefined *)((int)pfVar3 + 0x13) = uVar2;
  if (*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x47295) {
    uVar1 = FUN_80020078(0x1fc);
    if (((uVar1 != 0) || (uVar1 = FUN_80020078(0xeaf), uVar1 != 0)) ||
       (2 < *(byte *)((int)pfVar3 + 0x13))) {
      *(float *)(param_1 + 6) = *(float *)(param_1 + 6) - FLOAT_803e6b98;
    }
  }
  else if ((*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x4a5e6) &&
          (5 < *(byte *)((int)pfVar3 + 0x13))) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + FLOAT_803e6b98;
  }
  return;
}

