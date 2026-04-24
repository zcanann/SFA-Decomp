// Function: FUN_8025aaf4
// Entry: 8025aaf4
// Size: 20 bytes

undefined4 FUN_8025aaf4(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(DAT_803dc5a8 + 0x410);
  *(undefined4 *)(DAT_803dc5a8 + 0x410) = param_1;
  return uVar1;
}

