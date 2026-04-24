// Function: FUN_801f63cc
// Entry: 801f63cc
// Size: 376 bytes

void FUN_801f63cc(undefined2 *param_1,int param_2)

{
  undefined uVar2;
  int iVar1;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_801f5690;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  param_1[1] = (short)((int)*(short *)(param_2 + 0x1a) << 8);
  *pfVar3 = ((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1c) ^ 0x80000000) -
                    DOUBLE_803e5f08) / FLOAT_803e5ef8) / FLOAT_803e5efc;
  pfVar3[1] = 0.0;
  *(undefined2 *)(pfVar3 + 2) = 0;
  *(undefined2 *)((int)pfVar3 + 10) = 0;
  *(undefined2 *)((int)pfVar3 + 0xe) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)(pfVar3 + 3) = *(undefined2 *)(param_2 + 0x20);
  *(short *)(pfVar3 + 4) = (short)*(char *)(param_2 + 0x19);
  *(byte *)((int)pfVar3 + 0x15) = *(byte *)((int)pfVar3 + 0x15) & 0x7f;
  param_1[0x58] = param_1[0x58] | 0x6000;
  uVar2 = (**(code **)(*DAT_803dcaac + 0x40))((int)*(char *)(param_1 + 0x56));
  *(undefined *)((int)pfVar3 + 0x13) = uVar2;
  if (*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x47295) {
    iVar1 = FUN_8001ffb4(0x1fc);
    if (((iVar1 != 0) || (iVar1 = FUN_8001ffb4(0xeaf), iVar1 != 0)) ||
       (2 < *(byte *)((int)pfVar3 + 0x13))) {
      *(float *)(param_1 + 6) = *(float *)(param_1 + 6) - FLOAT_803e5f00;
    }
  }
  else if ((*(int *)(*(int *)(param_1 + 0x26) + 0x14) == 0x4a5e6) &&
          (5 < *(byte *)((int)pfVar3 + 0x13))) {
    *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + FLOAT_803e5f00;
  }
  return;
}

