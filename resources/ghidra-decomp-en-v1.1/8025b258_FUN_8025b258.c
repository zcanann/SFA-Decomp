// Function: FUN_8025b258
// Entry: 8025b258
// Size: 20 bytes

undefined4 FUN_8025b258(undefined4 param_1)

{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(DAT_803dd210 + 0x410);
  *(undefined4 *)(DAT_803dd210 + 0x410) = param_1;
  return uVar1;
}

