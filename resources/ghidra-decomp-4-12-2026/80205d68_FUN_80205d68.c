// Function: FUN_80205d68
// Entry: 80205d68
// Size: 148 bytes

void FUN_80205d68(undefined2 *param_1,int param_2)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0x5c);
  *(code **)(param_1 + 0x5e) = FUN_802057a0;
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *pfVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                   DOUBLE_803e7058);
  *(undefined2 *)(pfVar1 + 2) = *(undefined2 *)(param_2 + 0x1c);
  *(undefined *)((int)pfVar1 + 0xe) = *(undefined *)(param_2 + 0x19);
  *(undefined2 *)(pfVar1 + 1) = *(undefined2 *)(param_2 + 0x1e);
  *(undefined2 *)((int)pfVar1 + 6) = *(undefined2 *)(param_2 + 0x20);
  param_1[0x58] = param_1[0x58] | 0x2000;
  *(byte *)((int)pfVar1 + 0xf) = *(byte *)((int)pfVar1 + 0xf) & 0x7f;
  return;
}

