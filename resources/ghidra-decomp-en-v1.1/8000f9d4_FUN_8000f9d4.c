// Function: FUN_8000f9d4
// Entry: 8000f9d4
// Size: 188 bytes

void FUN_8000f9d4(void)

{
  if (*(char *)(DAT_803dd970 + 0x18) == '\0') {
    FUN_8025da64((double)FLOAT_803df28c,(double)FLOAT_803df28c,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                                DOUBLE_803df2b8),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803df2b8),(double)FLOAT_803df2c8,(double)FLOAT_803df270);
  }
  else {
    FUN_8025d948((double)FLOAT_803df28c,(double)FLOAT_803df28c,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                                DOUBLE_803df2b8),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803df2b8),(double)FLOAT_803df2c8,(double)FLOAT_803df270,
                 DAT_803dd93c);
  }
  return;
}

