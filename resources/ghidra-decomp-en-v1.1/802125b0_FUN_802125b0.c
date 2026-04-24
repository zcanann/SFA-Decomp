// Function: FUN_802125b0
// Entry: 802125b0
// Size: 296 bytes

undefined4 FUN_802125b0(void)

{
  byte bVar1;
  byte bVar2;
  
  bVar1 = *(byte *)(DAT_803de9d4 + 0xfe);
  bVar2 = *(byte *)(DAT_803de9d4 + 0xff);
  if ((bVar1 & bVar2) != 0) {
    if ((*(ushort *)(DAT_803de9d4 + 0xfa) & 1) == 0) {
      if (*(float *)(DAT_803de9d4 + 0xf4) < *(float *)(DAT_803de9d4 + 8)) {
        return 1;
      }
    }
    else if (*(float *)(DAT_803de9d4 + 8) < *(float *)(DAT_803de9d4 + 0xf4)) {
      return 1;
    }
    return 0;
  }
  if ((*(ushort *)(DAT_803de9d4 + 0xfa) & 1) != 0) {
    if ((((bVar1 != 8) || ((bVar2 & 1) == 0)) && ((bVar1 != 2 || ((bVar2 & 8) == 0)))) &&
       (((bVar1 != 4 || ((bVar2 & 2) == 0)) && ((bVar1 != 1 || ((bVar2 & 4) == 0)))))) {
      return 0;
    }
    return 1;
  }
  if (((((bVar1 != 1) || ((bVar2 & 8) == 0)) && ((bVar1 != 4 || ((bVar2 & 1) == 0)))) &&
      ((bVar1 != 2 || ((bVar2 & 4) == 0)))) && ((bVar1 != 8 || ((bVar2 & 2) == 0)))) {
    return 0;
  }
  return 1;
}

