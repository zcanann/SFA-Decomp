// Function: FUN_8025b26c
// Entry: 8025b26c
// Size: 20 bytes

undefined4 FUN_8025b26c(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(DAT_803dd210 + 0x414);
  *(undefined4 *)(DAT_803dd210 + 0x414) = param_1;
  return uVar1;
}

