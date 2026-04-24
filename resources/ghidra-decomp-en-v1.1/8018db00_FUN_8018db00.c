// Function: FUN_8018db00
// Entry: 8018db00
// Size: 348 bytes

void FUN_8018db00(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  double dVar3;
  
  param_9[3] = param_9[3] | 2;
  uVar2 = *(byte *)(param_10 + 0x1c) ^ 0x80000000;
  fVar1 = (float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a68);
  if ((float)((double)CONCAT44(0x43300000,uVar2) - DOUBLE_803e4a68) < FLOAT_803e4a58) {
    fVar1 = FLOAT_803e4a58;
  }
  dVar3 = (double)(fVar1 * FLOAT_803e4a5c);
  *(float *)(param_9 + 4) = (float)((double)*(float *)(*(int *)(param_9 + 0x28) + 4) * dVar3);
  *param_9 = (short)((*(byte *)(param_10 + 0x1d) & 0x3f) << 10);
  if (*(float **)(param_9 + 0x32) != (float *)0x0) {
    **(float **)(param_9 + 0x32) = (float)((double)**(float **)(param_9 + 0x28) * dVar3);
  }
  *(undefined *)((int)param_9 + 0xad) = *(undefined *)(param_10 + 0x18);
  if (*(char *)(*(int *)(param_9 + 0x28) + 0x55) <= *(char *)((int)param_9 + 0xad)) {
    *(undefined *)((int)param_9 + 0xad) = 0;
  }
  FUN_8003042c((double)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_10 + 0x1a)) -
                               DOUBLE_803e4a50) * FLOAT_803e4a60),dVar3,param_3,param_4,param_5,
               param_6,param_7,param_8,param_9,(uint)*(byte *)(param_10 + 0x19),0,param_12,param_13,
               param_14,param_15,param_16);
  if ((int)*(short *)(param_10 + 0x20) != 0xffffffff) {
    uVar2 = FUN_80020078((int)*(short *)(param_10 + 0x20));
    if (uVar2 == 0) {
      *(undefined *)(param_9 + 0x1b) = 0;
    }
    else {
      *(undefined *)(param_9 + 0x1b) = 0xff;
    }
  }
  return;
}

