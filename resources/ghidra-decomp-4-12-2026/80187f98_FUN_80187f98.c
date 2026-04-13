// Function: FUN_80187f98
// Entry: 80187f98
// Size: 344 bytes

void FUN_80187f98(undefined2 *param_1,int param_2)

{
  uint uVar1;
  byte *pbVar2;
  undefined8 local_28;
  
  pbVar2 = *(byte **)(param_1 + 0x5c);
  FUN_800372f8((int)param_1,0x31);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000);
  *(float *)(param_1 + 4) = FLOAT_803e47b8 * ((float)(local_28 - DOUBLE_803e47d0) / FLOAT_803e47bc);
  if (*(float *)(param_1 + 4) <= FLOAT_803e47c0) {
    *(float *)(param_1 + 4) = FLOAT_803e47c0;
  }
  FUN_80035c48((int)param_1,(short)(int)(FLOAT_803e47c4 * *(float *)(param_1 + 4)),0,
               (short)(int)(FLOAT_803e47c8 * *(float *)(param_1 + 4)));
  *(float *)(pbVar2 + 0x10) = FLOAT_803e47cc;
  FUN_800303fc((double)FLOAT_803e4798,(int)param_1);
  if (((int)*(short *)(param_2 + 0x1e) != 0xffffffff) &&
     (uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e)), uVar1 != 0)) {
    FUN_8002cf80((int)param_1);
    FUN_80035ff8((int)param_1);
    *(undefined *)(param_1 + 0x1b) = 0;
    *pbVar2 = *pbVar2 | 2;
  }
  pbVar2[1] = *(byte *)(param_2 + 0x19);
  if (pbVar2[1] == 1) {
    FUN_80035f84((int)param_1);
  }
  return;
}

