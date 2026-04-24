// Function: FUN_80213568
// Entry: 80213568
// Size: 216 bytes

undefined4 FUN_80213568(undefined4 param_1,int param_2)

{
  float fVar1;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,0xb,0);
    FUN_8000bb18(param_1,0x454);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e680c;
    fVar1 = FLOAT_803e67b8;
    *(float *)(param_2 + 0x280) = FLOAT_803e67b8;
    *(float *)(param_2 + 0x284) = fVar1;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x80000;
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 0x80) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xffffff7f;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x20000;
  }
  return 0;
}

