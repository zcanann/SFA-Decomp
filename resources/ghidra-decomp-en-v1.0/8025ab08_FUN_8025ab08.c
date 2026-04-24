// Function: FUN_8025ab08
// Entry: 8025ab08
// Size: 20 bytes

undefined4 FUN_8025ab08(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(DAT_803dc5a8 + 0x414);
  *(undefined4 *)(DAT_803dc5a8 + 0x414) = param_1;
  return uVar1;
}

