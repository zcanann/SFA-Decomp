// Function: FUN_80213f8c
// Entry: 80213f8c
// Size: 648 bytes

undefined4
FUN_80213f8c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined2 *param_9,
            int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  float fStack_88;
  ushort local_84 [4];
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float afStack_6c [17];
  undefined8 local_28;
  undefined8 local_20;
  
  uVar1 = *(ushort *)(DAT_803de9d4 + 0xfa);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_8032b168 +
                                        ((uint)*(byte *)(DAT_803de9d4 + 0xfc) * 2 + (uVar1 & 1)) * 2
                                        ),0,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2a0) =
         *(undefined4 *)(&DAT_8032b180 + (uint)*(byte *)(DAT_803de9d4 + 0xfc) * 4);
    *(undefined2 *)(DAT_803de9d4 + 0xf8) = *param_9;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 4) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffb;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 1;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 2) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffd;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 2;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x40;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 0x80) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xffffff7f;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x10000;
  }
  *(byte *)(param_10 + 0x34c) = *(byte *)(param_10 + 0x34c) | 1;
  (**(code **)(*DAT_803dd70c + 0x20))((double)FLOAT_803dc074,param_9,param_10,3);
  local_84[0] = *(ushort *)(DAT_803de9d4 + 0xf8);
  local_84[1] = 0;
  local_84[2] = 0;
  local_7c = FLOAT_803e74b0;
  local_78 = FLOAT_803e7450;
  local_74 = FLOAT_803e7450;
  local_70 = FLOAT_803e7450;
  FUN_80021fac(afStack_6c,local_84);
  FUN_80022790((double)*(float *)(param_10 + 0x284),(double)FLOAT_803e7450,
               -(double)*(float *)(param_10 + 0x280),afStack_6c,(float *)(param_9 + 0x12),&fStack_88
               ,(float *)(param_9 + 0x16));
  if ((uVar1 & 1) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803de9d4 + 0xf8) ^ 0x80000000);
    *param_9 = (short)(int)-(FLOAT_803e74b4 * *(float *)(param_9 + 0x4c) -
                            (float)(local_20 - DOUBLE_803e7498));
  }
  else {
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803de9d4 + 0xf8) ^ 0x80000000);
    *param_9 = (short)(int)(FLOAT_803e74b4 * *(float *)(param_9 + 0x4c) +
                           (float)(local_28 - DOUBLE_803e7498));
  }
  return 0;
}

