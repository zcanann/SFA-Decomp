// Function: FUN_8000f7a0
// Entry: 8000f7a0
// Size: 188 bytes

void FUN_8000f7a0(void)

{
  double dVar1;
  
  if (*(char *)(DAT_803dd970 + 0x18) == '\0') {
    dVar1 = (double)FLOAT_803df28c;
    FUN_8025da64(dVar1,dVar1,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                                DOUBLE_803df2b8),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803df2b8),dVar1,(double)FLOAT_803df270);
  }
  else {
    dVar1 = (double)FLOAT_803df28c;
    FUN_8025d948(dVar1,dVar1,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 4)) -
                                DOUBLE_803df2b8),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dd970 + 6)) -
                                DOUBLE_803df2b8),dVar1,(double)FLOAT_803df270,DAT_803dd93c);
  }
  return;
}

