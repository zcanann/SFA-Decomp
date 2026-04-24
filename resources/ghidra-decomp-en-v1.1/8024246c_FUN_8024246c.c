// Function: FUN_8024246c
// Entry: 8024246c
// Size: 152 bytes

void FUN_8024246c(void)

{
  uint uVar1;
  
  sync(0);
  FUN_80240a64();
  FUN_80240a6c();
  sync(0);
  FUN_80240a64();
  FUN_80240a6c();
  do {
    uVar1 = FUN_80240a64();
  } while ((uVar1 & 1) != 0);
  FUN_80240a64();
  FUN_80240a6c();
  while (uVar1 = FUN_80240a64(), (uVar1 & 1) != 0) {
    FUN_80247568();
  }
  return;
}

