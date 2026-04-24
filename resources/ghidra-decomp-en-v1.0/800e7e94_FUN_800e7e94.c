// Function: FUN_800e7e94
// Entry: 800e7e94
// Size: 68 bytes

undefined4 FUN_800e7e94(uint param_1)

{
  uint uVar1;
  
  uVar1 = 1 << (param_1 & 0xff);
  if (((DAT_803a31d4 & uVar1) != 0) && ((DAT_803a31d8 & uVar1) != 0)) {
    return 1;
  }
  return 0;
}

