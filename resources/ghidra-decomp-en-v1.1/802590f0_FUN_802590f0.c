// Function: FUN_802590f0
// Entry: 802590f0
// Size: 136 bytes

void FUN_802590f0(void)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = (uint)*(ushort *)(DAT_803dd210 + 4) * (uint)*(ushort *)(DAT_803dd210 + 6);
  DAT_cc008000._0_1_ = 0x98;
  DAT_cc008000._0_2_ = *(ushort *)(DAT_803dd210 + 4);
  uVar1 = iVar3 + 3;
  uVar2 = uVar1 >> 2;
  if (iVar3 != 0) {
    uVar1 = uVar1 >> 5;
    if (uVar1 != 0) {
      do {
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        DAT_cc008000 = 0;
        uVar1 = uVar1 - 1;
      } while (uVar1 != 0);
      uVar2 = uVar2 & 7;
      if (uVar2 == 0) goto LAB_80259168;
    }
    do {
      DAT_cc008000 = 0;
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
  }
LAB_80259168:
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  return;
}

