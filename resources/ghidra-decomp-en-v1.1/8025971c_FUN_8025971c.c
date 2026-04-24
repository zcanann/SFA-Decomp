// Function: FUN_8025971c
// Entry: 8025971c
// Size: 212 bytes

uint FUN_8025971c(double param_1)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar1 = FUN_80286718((double)(float)((double)FLOAT_803e8310 / param_1));
  uVar1 = uVar1 & 0x1ff;
  DAT_cc008000._0_1_ = 0x61;
  DAT_cc008000 = uVar1 | 0x4e000000;
  iVar2 = -uVar1 + 0x100;
  *(undefined2 *)(DAT_803dd210 + 2) = 0;
  *(uint *)(DAT_803dd210 + 0x1ec) =
       *(uint *)(DAT_803dd210 + 0x1ec) & 0xfffffbff |
       (iVar2 - ((uint)(iVar2 == 0) + -uVar1 + 0xff)) * 0x400 & 0x3fc00;
  uVar3 = (*(uint *)(DAT_803dd210 + 0x1e4) >> 2 & 0x3ff00) / uVar1;
  uVar5 = (*(uint *)(DAT_803dd210 + 0x1e4) >> 10 & 0x3ff) + 1;
  uVar4 = uVar3 + 1;
  if ((0x80 < uVar1) && (uVar1 < 0x100)) {
    for (; (uVar1 & 1) == 0; uVar1 = uVar1 >> 1) {
    }
    if (uVar5 == (uVar5 / uVar1) * uVar1) {
      uVar4 = uVar3 + 2;
    }
  }
  if (0x400 < uVar4) {
    uVar4 = 0x400;
  }
  return uVar4;
}

