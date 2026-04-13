// Function: FUN_802880e4
// Entry: 802880e4
// Size: 152 bytes

void FUN_802880e4(void)

{
  undefined *puVar1;
  byte local_18 [4];
  undefined auStack_14 [8];
  int local_c;
  
  local_c = FUN_8028817c();
  if (local_c != -1) {
    puVar1 = FUN_80287f00(local_c);
    FUN_80287e2c((int)puVar1,0);
    FUN_80287a2c((int)puVar1,(int)local_18);
    if (local_18[0] < 0x80) {
      FUN_802870dc(auStack_14,2);
      DAT_803d8f34 = 0xffffffff;
      FUN_802870f4((int)auStack_14);
    }
    else {
      FUN_80287e9c(local_c);
    }
  }
  return;
}

