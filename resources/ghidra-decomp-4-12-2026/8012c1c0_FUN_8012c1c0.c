// Function: FUN_8012c1c0
// Entry: 8012c1c0
// Size: 380 bytes

void FUN_8012c1c0(void)

{
  char cVar1;
  uint uVar2;
  char local_18;
  undefined auStack_17 [15];
  
  cVar1 = DAT_803de3db;
  if (DAT_803de400 == '\0') {
    uVar2 = FUN_80014e9c(0);
    FUN_80014ba4(0,auStack_17,&local_18);
    if (local_18 == '\x01') {
      DAT_803de3db = '\x01';
    }
    if (local_18 == -1) {
      DAT_803de3db = '\x02';
    }
    if (DAT_803de3db != cVar1) {
      FUN_8000bb38(0,0xf3);
    }
    if ((uVar2 & 0x100) != 0) {
      FUN_80014b68(0,0x100);
      if (DAT_803de3db == '\x01') {
        FUN_800201ac(0x2b3,1);
      }
      else {
        FUN_800201ac(0x781,1);
      }
      DAT_803de3db = '\0';
      FUN_800207ac(0);
      (**(code **)(*DAT_803dd6d0 + 0x24))(3,0x80,1);
      DAT_803de408 = 0x3c;
      FUN_8000bb38(0,0x418);
    }
    if ((uVar2 & 0x200) != 0) {
      FUN_80014b68(0,0x200);
      DAT_803de3db = '\0';
      FUN_800207ac(0);
      (**(code **)(*DAT_803dd6d0 + 0x24))(3,0x80,1);
      DAT_803de408 = 0x3c;
      FUN_8000bb38(0,0x419);
    }
  }
  return;
}

