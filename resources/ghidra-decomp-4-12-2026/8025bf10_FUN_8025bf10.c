// Function: FUN_8025bf10
// Entry: 8025bf10
// Size: 204 bytes

void FUN_8025bf10(undefined4 param_1,undefined4 param_2,uint param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  uVar3 = 0;
  iVar2 = 0;
  for (uVar1 = *(uint *)(DAT_803dd210 + 0x204) >> 0x10 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
    if (iVar2 == 2) {
      param_3 = *(uint *)(DAT_803dd210 + 0x120) >> 0xc & 7;
    }
    else if (iVar2 < 2) {
      if (iVar2 == 0) {
        param_3 = *(uint *)(DAT_803dd210 + 0x120) & 7;
      }
      else if (-1 < iVar2) {
        param_3 = *(uint *)(DAT_803dd210 + 0x120) >> 6 & 7;
      }
    }
    else if (iVar2 < 4) {
      param_3 = *(uint *)(DAT_803dd210 + 0x120) >> 0x12 & 7;
    }
    uVar3 = uVar3 | 1 << param_3;
    iVar2 = iVar2 + 1;
  }
  if ((*(uint *)(DAT_803dd210 + 0x124) & 0xff) == uVar3) {
    return;
  }
  *(uint *)(DAT_803dd210 + 0x124) = *(uint *)(DAT_803dd210 + 0x124) & 0xffffff00 | uVar3;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = *(undefined4 *)(DAT_803dd210 + 0x124);
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  return;
}

