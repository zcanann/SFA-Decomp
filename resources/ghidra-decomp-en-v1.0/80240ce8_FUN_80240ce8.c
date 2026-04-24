// Function: FUN_80240ce8
// Entry: 80240ce8
// Size: 56 bytes

undefined4 FUN_80240ce8(void)

{
  uint uVar1;
  
  uVar1 = FUN_80240384();
  FUN_8024038c(uVar1 | 0xa0000000);
  FUN_80241b18();
  sync(0);
  return 0;
}

