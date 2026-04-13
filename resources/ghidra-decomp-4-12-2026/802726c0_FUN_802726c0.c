// Function: FUN_802726c0
// Entry: 802726c0
// Size: 84 bytes

undefined4 FUN_802726c0(uint param_1)

{
  uint uVar1;
  
  uVar1 = param_1 & 0xff;
  if ((((&DAT_803bdff1)[uVar1 * 0x30] != '\x04') && ((DAT_803deee0 & 1 << uVar1) != 0)) &&
     ((float)(&DAT_803bdfc8)[uVar1 * 0xc] < (float)(&DAT_803bdfcc)[uVar1 * 0xc])) {
    return 1;
  }
  return 0;
}

