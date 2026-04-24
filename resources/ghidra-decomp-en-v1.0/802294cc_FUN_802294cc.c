// Function: FUN_802294cc
// Entry: 802294cc
// Size: 148 bytes

undefined4 FUN_802294cc(int param_1,undefined4 param_2,int param_3)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  *pfVar1 = FLOAT_803e6e48 * -*pfVar1 * FLOAT_803db414 + *pfVar1;
  *(short *)(param_1 + 4) =
       (short)(int)(FLOAT_803db414 * *pfVar1 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 4) ^ 0x80000000) -
                          DOUBLE_803e6e50));
  *(undefined *)(param_3 + 0x56) = 0;
  *(ushort *)(param_3 + 0x70) = *(ushort *)(param_3 + 0x70) & 0xfffd;
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x6e) & 0xfffd;
  return 0;
}

