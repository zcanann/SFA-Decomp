// Function: FUN_80252758
// Entry: 80252758
// Size: 212 bytes

bool FUN_80252758(int param_1)

{
  bool bVar1;
  uint uVar2;
  
  FUN_8024377c();
  uVar2 = read_volatile_4(DAT_cc006438);
  uVar2 = uVar2 >> (3 - param_1) * 8;
  if (((uVar2 & 8) != 0) && ((*(uint *)(&DAT_8032e254 + param_1 * 4) & 0x80) == 0)) {
    *(uint *)(&DAT_8032e254 + param_1 * 4) = 8;
  }
  FUN_802437a4();
  bVar1 = (uVar2 & 0x20) != 0;
  if (bVar1) {
    *(undefined4 *)(&DAT_803ae3c0 + param_1 * 8) = *(undefined4 *)(&DAT_cc006404 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803ae3c4 + param_1 * 8) = *(undefined4 *)(&DAT_cc006408 + param_1 * 0xc);
    *(undefined4 *)(&DAT_803ae3b0 + param_1 * 4) = 1;
  }
  return bVar1;
}

