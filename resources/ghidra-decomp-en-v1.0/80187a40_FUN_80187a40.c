// Function: FUN_80187a40
// Entry: 80187a40
// Size: 344 bytes

void FUN_80187a40(undefined2 *param_1,int param_2)

{
  int iVar1;
  byte *pbVar2;
  double local_28;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  FUN_80037200(param_1,0x31);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000);
  *(float *)(param_1 + 4) = FLOAT_803e3b20 * ((float)(local_28 - DOUBLE_803e3b38) / FLOAT_803e3b24);
  if (*(float *)(param_1 + 4) <= FLOAT_803e3b28) {
    *(float *)(param_1 + 4) = FLOAT_803e3b28;
  }
  FUN_80035b50(param_1,(int)(short)(int)(FLOAT_803e3b2c * *(float *)(param_1 + 4)),0,
               (int)(short)(int)(FLOAT_803e3b30 * *(float *)(param_1 + 4)));
  *(float *)(pbVar2 + 0x10) = FLOAT_803e3b34;
  FUN_80030304((double)FLOAT_803e3b00,param_1);
  if ((*(short *)(param_2 + 0x1e) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    FUN_8002ce88(param_1);
    FUN_80035f00(param_1);
    *(undefined *)(param_1 + 0x1b) = 0;
    *pbVar2 = *pbVar2 | 2;
  }
  pbVar2[1] = *(byte *)(param_2 + 0x19);
  if (pbVar2[1] == 1) {
    FUN_80035e8c(param_1);
  }
  return;
}

