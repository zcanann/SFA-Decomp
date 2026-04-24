// Function: FUN_8008ed88
// Entry: 8008ed88
// Size: 96 bytes

double FUN_8008ed88(void)

{
  float fVar1;
  
  fVar1 = FLOAT_803df1a0;
  if (DAT_803dd19c != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,
                                     (uint)*(ushort *)(DAT_803dd19c + 0x22) -
                                     (uint)*(ushort *)(DAT_803dd19c + 0x20) ^ 0x80000000) -
                   DOUBLE_803df1a8) /
            (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd19c + 0x22)) -
                   DOUBLE_803df1b0);
  }
  return (double)fVar1;
}

