// Function: FUN_80213914
// Entry: 80213914
// Size: 648 bytes

undefined4 FUN_80213914(undefined2 *param_1,int param_2)

{
  ushort uVar1;
  undefined auStack136 [4];
  undefined2 local_84;
  undefined2 local_82;
  undefined2 local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined auStack108 [68];
  double local_28;
  double local_20;
  
  uVar1 = *(ushort *)(DAT_803ddd54 + 0xfa);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,
                 (int)*(short *)(&DAT_8032a510 +
                                ((uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2 + (uVar1 & 1)) * 2),0);
    *(undefined4 *)(param_2 + 0x2a0) =
         *(undefined4 *)(&DAT_8032a528 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 4);
    *(undefined2 *)(DAT_803ddd54 + 0xf8) = *param_1;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 4) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffb;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 1;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 2) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffd;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 2;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x40;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 0x80) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xffffff7f;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x10000;
  }
  *(byte *)(param_2 + 0x34c) = *(byte *)(param_2 + 0x34c) | 1;
  (**(code **)(*DAT_803dca8c + 0x20))((double)FLOAT_803db414,param_1,param_2,3);
  local_84 = *(undefined2 *)(DAT_803ddd54 + 0xf8);
  local_82 = 0;
  local_80 = 0;
  local_7c = FLOAT_803e6818;
  local_78 = FLOAT_803e67b8;
  local_74 = FLOAT_803e67b8;
  local_70 = FLOAT_803e67b8;
  FUN_80021ee8(auStack108,&local_84);
  FUN_800226cc((double)*(float *)(param_2 + 0x284),(double)FLOAT_803e67b8,
               -(double)*(float *)(param_2 + 0x280),auStack108,param_1 + 0x12,auStack136,
               param_1 + 0x16);
  if ((uVar1 & 1) == 0) {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803ddd54 + 0xf8) ^ 0x80000000);
    *param_1 = (short)(int)-(FLOAT_803e681c * *(float *)(param_1 + 0x4c) -
                            (float)(local_20 - DOUBLE_803e6800));
  }
  else {
    local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(DAT_803ddd54 + 0xf8) ^ 0x80000000);
    *param_1 = (short)(int)(FLOAT_803e681c * *(float *)(param_1 + 0x4c) +
                           (float)(local_28 - DOUBLE_803e6800));
  }
  return 0;
}

