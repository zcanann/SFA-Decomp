// Function: FUN_802137f8
// Entry: 802137f8
// Size: 284 bytes

undefined4 FUN_802137f8(undefined2 *param_1,int param_2)

{
  ushort uVar1;
  float fVar2;
  double local_28;
  double local_20;
  
  uVar1 = *(ushort *)(DAT_803ddd54 + 0xfa);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,0xf,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6810;
    fVar2 = FLOAT_803e67b8;
    *(float *)(param_2 + 0x280) = FLOAT_803e67b8;
    *(float *)(param_2 + 0x284) = fVar2;
    *(undefined2 *)(DAT_803ddd54 + 0xf8) = *param_1;
  }
  if ((uVar1 & 1) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803ddd54 + 0xf8) ^ 0x80000000);
    *param_1 = (short)(int)-(FLOAT_803e6814 * *(float *)(param_1 + 0x4c) -
                            (float)(local_20 - DOUBLE_803e6800));
  }
  else {
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803ddd54 + 0xf8) ^ 0x80000000);
    *param_1 = (short)(int)(FLOAT_803e6814 * *(float *)(param_1 + 0x4c) +
                           (float)(local_28 - DOUBLE_803e6800));
  }
  return 0;
}

