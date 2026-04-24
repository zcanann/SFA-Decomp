// Function: FUN_80241d74
// Entry: 80241d74
// Size: 152 bytes

void FUN_80241d74(void)

{
  uint uVar1;
  
  sync(0);
  uVar1 = FUN_8024036c();
  FUN_80240374(uVar1 & 0x7fffffff);
  sync(0);
  uVar1 = FUN_8024036c();
  FUN_80240374(uVar1 | 0x200000);
  do {
    uVar1 = FUN_8024036c();
  } while ((uVar1 & 1) != 0);
  uVar1 = FUN_8024036c();
  FUN_80240374(uVar1 & 0xffdfffff);
  while (uVar1 = FUN_8024036c(), (uVar1 & 1) != 0) {
    FUN_80246e04(s_____L2_INVALIDATE___SHOULD_NEVER_8032c5a0);
  }
  return;
}

