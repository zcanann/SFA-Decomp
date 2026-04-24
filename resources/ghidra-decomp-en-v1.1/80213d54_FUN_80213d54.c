// Function: FUN_80213d54
// Entry: 80213d54
// Size: 284 bytes

undefined4
FUN_80213d54(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,int param_10
            ,undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  ushort uVar1;
  float fVar2;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e7450,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_803dcec8 + (uint)*(byte *)(DAT_803de9d4 + 0xfd) * 2),0
                 ,param_12,param_13,param_14,param_15,param_16);
    *(undefined4 *)(param_10 + 0x2a0) =
         *(undefined4 *)(&DAT_8032b174 + (uint)*(byte *)(DAT_803de9d4 + 0xfd) * 4);
    fVar2 = FLOAT_803e7450;
    *(float *)(param_10 + 0x280) = FLOAT_803e7450;
    *(float *)(param_10 + 0x284) = fVar2;
  }
  uVar1 = *(ushort *)(&DAT_803dcef0 + (uint)*(byte *)(DAT_803de9d4 + 0xfd) * 2);
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | (uint)uVar1;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 0x200) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffdff;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x800;
  }
  if ((*(uint *)(DAT_803de9d8 + 0x314) & 0x400) != 0) {
    *(uint *)(DAT_803de9d8 + 0x314) = *(uint *)(DAT_803de9d8 + 0x314) & 0xfffffbff;
    *(uint *)(DAT_803de9d4 + 0x104) = *(uint *)(DAT_803de9d4 + 0x104) | 0x1000;
  }
  return 0;
}

