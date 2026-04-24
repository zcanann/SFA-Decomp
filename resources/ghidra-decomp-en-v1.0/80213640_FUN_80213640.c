// Function: FUN_80213640
// Entry: 80213640
// Size: 156 bytes

undefined4 FUN_80213640(undefined4 param_1,int param_2)

{
  float fVar1;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,
                 (int)*(short *)(&DAT_803dc250 + (uint)*(byte *)(DAT_803ddd54 + 0xfc) * 2),0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e6810;
    fVar1 = FLOAT_803e67b8;
    *(float *)(param_2 + 0x280) = FLOAT_803e67b8;
    *(float *)(param_2 + 0x284) = fVar1;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x200;
  }
  return 0;
}

