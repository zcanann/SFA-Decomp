// Function: FUN_8000f9b4
// Entry: 8000f9b4
// Size: 188 bytes

void FUN_8000f9b4(void)

{
  if (*(char *)(DAT_803dccf0 + 0x18) == '\0') {
    FUN_8025d300((double)FLOAT_803de60c,(double)FLOAT_803de60c,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                                DOUBLE_803de638),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803de638),(double)FLOAT_803de648,(double)FLOAT_803de5f0);
  }
  else {
    FUN_8025d1e4((double)FLOAT_803de60c,(double)FLOAT_803de60c,
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 4)) -
                                DOUBLE_803de638),
                 (double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803dccf0 + 8)) -
                                DOUBLE_803de638),(double)FLOAT_803de648,(double)FLOAT_803de5f0,
                 DAT_803dccbc);
  }
  return;
}

