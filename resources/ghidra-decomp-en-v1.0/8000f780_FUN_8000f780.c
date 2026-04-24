// Function: FUN_8000f780
// Entry: 8000f780
// Size: 188 bytes

void FUN_8000f780(void)

{
  double dVar1;
  
  if (*(char *)(DAT_803dccf0 + 0x18) == '\0') {
    dVar1 = (double)FLOAT_803de60c;
    FUN_8025d300(dVar1,dVar1,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                                DOUBLE_803de638),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803de638),dVar1,(double)FLOAT_803de5f0);
  }
  else {
    dVar1 = (double)FLOAT_803de60c;
    FUN_8025d1e4(dVar1,dVar1,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                                DOUBLE_803de638),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803de638),dVar1,(double)FLOAT_803de5f0,DAT_803dccbc);
  }
  return;
}

