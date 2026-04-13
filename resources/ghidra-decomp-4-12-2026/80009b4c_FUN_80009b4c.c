// Function: FUN_80009b4c
// Entry: 80009b4c
// Size: 132 bytes

void FUN_80009b4c(void)

{
  DAT_803dd440 = 1;
  FUN_8000b644();
  FUN_8000a3a0(1,1,0);
  FUN_8000a3a0(2,1,0);
  FUN_8000d03c();
  DAT_803dd444 = DAT_803dd444 & 0xfffffff0;
  DAT_803dd440 = 1;
  if ((DAT_803de288 == 2) || (DAT_803de288 == 3)) {
    FUN_80117e10(0,500);
  }
  FUN_8000d0e0();
  return;
}

