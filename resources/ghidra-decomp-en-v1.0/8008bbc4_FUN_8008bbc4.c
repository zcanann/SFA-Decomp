// Function: FUN_8008bbc4
// Entry: 8008bbc4
// Size: 484 bytes

void FUN_8008bbc4(void)

{
  bool bVar1;
  int iVar2;
  
  bVar1 = false;
  while (iVar2 = FUN_800430ac(0), iVar2 != 0) {
    FUN_80014f40();
    FUN_800202cc();
    if (bVar1) {
      FUN_8004a868();
    }
    FUN_800481d4();
    FUN_80015624();
    if (bVar1) {
      FUN_800234ec(0);
      FUN_80019c24();
      FUN_8004a43c(1,0);
    }
    if (DAT_803dc950 != '\0') {
      bVar1 = true;
    }
  }
  DAT_803dd164 = 0;
  DAT_803dd15c = 0;
  DAT_803dd158 = 0xff;
  uRam803dd159 = 0xff;
  uRam803dd15a = 0xff;
  if (DAT_803dd144 == 0) {
    DAT_803dd144 = FUN_8001f4c8(0,1);
    if (DAT_803dd144 != 0) {
      FUN_8001db2c(DAT_803dd144,4);
      FUN_8001dc90((double)FLOAT_803df058,(double)FLOAT_803df06c,(double)FLOAT_803df058,DAT_803dd144
                  );
      FUN_8001daf0(DAT_803dd144,0xff,0xff,0xff,0xff);
      FUN_8001da18(DAT_803dd144,0xff,0xff,0xff,0xff);
    }
    DAT_803dd168 = FUN_8001f4c8(0,1);
    if (DAT_803dd168 != 0) {
      FUN_8001db2c(DAT_803dd168,4);
      FUN_8001dc90((double)FLOAT_803df058,(double)FLOAT_803df05c,(double)FLOAT_803df058,DAT_803dd168
                  );
      FUN_8001daf0(DAT_803dd168,0xff,0xff,0xff,0xff);
      FUN_8001da18(DAT_803dd168,0xff,0xff,0xff,0xff);
    }
  }
  FUN_8008bda8();
  FUN_80088c94(7,0);
  FUN_80088e54((double)FLOAT_803df058,0);
  FUN_8008a500();
  FUN_8008a04c();
  DAT_8030f2c8 = FLOAT_803df058;
  DAT_8030f2cc = FLOAT_803df06c;
  DAT_8030f2d0 = FLOAT_803df058;
  DAT_8030f2d4 = FLOAT_803df058;
  DAT_8030f2d8 = FLOAT_803df06c;
  DAT_8030f2dc = FLOAT_803df058;
  DAT_803dd150 = FUN_80054d54(0x5fa);
  return;
}

