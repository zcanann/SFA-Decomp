// Function: FUN_80009b4c
// Entry: 80009b4c
// Size: 132 bytes

void FUN_80009b4c(void)

{
  DAT_803dc7c0 = 1;
  FUN_8000b624();
  FUN_8000a380(1,1,0);
  FUN_8000a380(2,1,0);
  FUN_8000d01c();
  DAT_803dc7c4 = DAT_803dc7c4 & 0xfffffff0;
  DAT_803dc7c0 = 1;
  if ((DAT_803dd610 == 2) || (DAT_803dd610 == 3)) {
    FUN_80117b68(0,500);
  }
  FUN_8000d0c0();
  return;
}

