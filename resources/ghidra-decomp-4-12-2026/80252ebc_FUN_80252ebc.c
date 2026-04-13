// Function: FUN_80252ebc
// Entry: 80252ebc
// Size: 212 bytes

bool FUN_80252ebc(int param_1)

{
  bool bVar1;
  uint uVar2;
  
  FUN_80243e74();
  uVar2 = DAT_cc006438;
  uVar2 = uVar2 >> (3 - param_1) * 8;
  if (((uVar2 & 8) != 0) && ((*(uint *)(&DAT_8032eeac + param_1 * 4) & 0x80) == 0)) {
    *(uint *)(&DAT_8032eeac + param_1 * 4) = 8;
  }
  FUN_80243e9c();
  bVar1 = (uVar2 & 0x20) != 0;
  if (bVar1) {
    *(undefined4 *)(&DAT_803af020 + param_1 * 8) = *(undefined4 *)(&DAT_cc006404 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803af024 + param_1 * 8) = *(undefined4 *)(&DAT_cc006408 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803af010 + param_1 * 4) = 1;
  }
  return bVar1;
}

