// Function: FUN_802133f0
// Entry: 802133f0
// Size: 200 bytes

undefined4 FUN_802133f0(undefined4 param_1,int param_2)

{
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e67b8,param_1,0xd,0);
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e67f8 *
         (float)((double)CONCAT44(0x43300000,
                                  (int)(uint)*(byte *)(DAT_803ddd54 + 0x101) >> 1 ^ 0x80000000) -
                DOUBLE_803e6800) + FLOAT_803e67f4;
    FUN_8000bb18(param_1,0x88);
  }
  if ((*(uint *)(DAT_803ddd58 + 0x314) & 1) != 0) {
    *(uint *)(DAT_803ddd58 + 0x314) = *(uint *)(DAT_803ddd58 + 0x314) & 0xfffffffe;
    *(uint *)(DAT_803ddd54 + 0x104) = *(uint *)(DAT_803ddd54 + 0x104) | 0x2000;
  }
  return 0;
}

