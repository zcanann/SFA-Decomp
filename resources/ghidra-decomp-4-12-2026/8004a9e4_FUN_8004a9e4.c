// Function: FUN_8004a9e4
// Entry: 8004a9e4
// Size: 444 bytes

void FUN_8004a9e4(void)

{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  
  FUN_802461cc(-0x7fc9fd20);
  uVar4 = FUN_80246298(-0x7fc9fd20);
  dVar3 = FUN_80286cd0((uint)((ulonglong)uVar4 >> 0x20),(uint)uVar4);
  FLOAT_803dd940 =
       (float)(dVar3 / (double)(float)((double)CONCAT44(0x43300000,DAT_800000f8 / 4000) -
                                      DOUBLE_803df700));
  FUN_80246308(-0x7fc9fd20);
  FUN_80246190(-0x7fc9fd20);
  FLOAT_803dc074 = FLOAT_803df71c * FLOAT_803df720 * FLOAT_803dd940;
  if (DAT_803dd5d0 != '\0') {
    FLOAT_803dc074 = FLOAT_803df6f0;
  }
  if (FLOAT_803df6f4 < FLOAT_803dc074) {
    FLOAT_803dc074 = FLOAT_803df6f4;
  }
  FLOAT_803dc078 = FLOAT_803df6f8;
  if (FLOAT_803df6fc < FLOAT_803dc074) {
    FLOAT_803dc078 = FLOAT_803df6f8 / FLOAT_803dc074;
  }
  uVar2 = (uint)(FLOAT_803dc074 + FLOAT_803dd934);
  uVar1 = uVar2 & 0xff;
  DAT_803dc071 = (undefined)uVar2;
  FLOAT_803dd934 =
       (FLOAT_803dc074 + FLOAT_803dd934) -
       (float)((double)CONCAT44(0x43300000,uVar1) - DOUBLE_803df700);
  DAT_803dc070 = DAT_803dc071;
  if (uVar1 == 0) {
    DAT_803dc070 = 1;
  }
  FUN_80243e74();
  DAT_803dd95c = FUN_802464ec();
  if (*(short *)(DAT_803dd95c + 0x2c8) != 2) {
    FUN_8007d858();
  }
  uVar2 = FUN_80013774((short *)&DAT_80360390);
  if (1 < uVar2) {
    DAT_803dd92c = 0;
    FUN_802471c4((int *)&DAT_803dd944);
  }
  FUN_80243e9c();
  FUN_8000f7a0();
  FUN_80258664();
  FUN_8025b210();
  return;
}

