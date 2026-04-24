// Function: FUN_80213e70
// Entry: 80213e70
// Size: 284 bytes

undefined4
FUN_80213e70(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined2 *param_9,
            int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  float fVar2;
  undefined8 local_28;
  undefined8 local_20;
  
  uVar1 = *(ushort *)(DAT_803de9d4 + 0xfa);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0xf,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e74a8;
    fVar2 = FLOAT_803e7450;
    *(float *)(param_10 + 0x280) = FLOAT_803e7450;
    *(float *)(param_10 + 0x284) = fVar2;
    *(undefined2 *)(DAT_803de9d4 + 0xf8) = *param_9;
  }
  if ((uVar1 & 1) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803de9d4 + 0xf8) ^ 0x80000000);
    *param_9 = (short)(int)-(FLOAT_803e74ac * *(float *)(param_9 + 0x4c) -
                            (float)(local_20 - DOUBLE_803e7498));
  }
  else {
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803de9d4 + 0xf8) ^ 0x80000000);
    *param_9 = (short)(int)(FLOAT_803e74ac * *(float *)(param_9 + 0x4c) +
                           (float)(local_28 - DOUBLE_803e7498));
  }
  return 0;
}

