// Function: FUN_8012be84
// Entry: 8012be84
// Size: 380 bytes

void FUN_8012be84(void)

{
  char cVar1;
  uint uVar2;
  char local_18;
  undefined auStack23 [15];
  
  cVar1 = DAT_803dd75b;
  if (DAT_803dd780 == '\0') {
    uVar2 = FUN_80014e70(0);
    FUN_80014b78(0,auStack23,&local_18);
    if (local_18 == '\x01') {
      DAT_803dd75b = '\x01';
    }
    if (local_18 == -1) {
      DAT_803dd75b = '\x02';
    }
    if (DAT_803dd75b != cVar1) {
      FUN_8000bb18(0,0xf3);
    }
    if ((uVar2 & 0x100) != 0) {
      FUN_80014b3c(0,0x100);
      if (DAT_803dd75b == '\x01') {
        FUN_800200e8(0x2b3,1);
      }
      else {
        FUN_800200e8(0x781,1);
      }
      DAT_803dd75b = '\0';
      FUN_800206e8(0);
      (**(code **)(*DAT_803dca50 + 0x24))(3,0x80,1);
      DAT_803dd788 = 0x3c;
      FUN_8000bb18(0,0x418);
    }
    if ((uVar2 & 0x200) != 0) {
      FUN_80014b3c(0,0x200);
      DAT_803dd75b = '\0';
      FUN_800206e8(0);
      (**(code **)(*DAT_803dca50 + 0x24))(3,0x80,1);
      DAT_803dd788 = 0x3c;
      FUN_8000bb18(0,0x419);
    }
  }
  return;
}

