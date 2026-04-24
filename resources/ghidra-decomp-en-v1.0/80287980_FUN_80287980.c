// Function: FUN_80287980
// Entry: 80287980
// Size: 152 bytes

void FUN_80287980(void)

{
  undefined4 uVar1;
  byte local_18 [4];
  undefined auStack20 [8];
  int local_c;
  
  local_c = FUN_80287a18();
  if (local_c != -1) {
    uVar1 = FUN_8028779c();
    FUN_802876c8(uVar1,0);
    FUN_802872c8(uVar1,local_18);
    if (local_18[0] < 0x80) {
      FUN_80286978(auStack20,2);
      DAT_803d82d4 = 0xffffffff;
      FUN_80286990(auStack20);
    }
    else {
      FUN_80287738(local_c);
    }
  }
  return;
}

