// Function: FUN_8008f014
// Entry: 8008f014
// Size: 96 bytes

double FUN_8008f014(void)

{
  float fVar1;
  
  fVar1 = FLOAT_803dfe20;
  if (DAT_803dde1c != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,
                                     (uint)*(ushort *)(DAT_803dde1c + 0x22) -
                                     (uint)*(ushort *)(DAT_803dde1c + 0x20) ^ 0x80000000) -
                   DOUBLE_803dfe28) /
            (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dde1c + 0x22)) -
                   DOUBLE_803dfe30);
  }
  return (double)fVar1;
}

