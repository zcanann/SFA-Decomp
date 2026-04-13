// Function: FUN_800298b8
// Entry: 800298b8
// Size: 84 bytes

void FUN_800298b8(void)

{
  uint uVar1;
  
  uVar1 = FUN_80240a7c();
  if ((uVar1 & 0x10000000) == 0) {
    uVar1 = FUN_80022b0c();
    FUN_802420b0(uVar1,0x4000);
    FUN_80242300();
  }
  FUN_8002983c();
  FUN_8002a4e4();
  return;
}

