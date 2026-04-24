// Function: FUN_80258fb8
// Entry: 80258fb8
// Size: 212 bytes

uint FUN_80258fb8(double param_1)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  uVar1 = FUN_80285fb4((double)(float)((double)FLOAT_803e7678 / param_1));
  uVar1 = uVar1 & 0x1ff;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,uVar1 | 0x4e000000);
  iVar2 = -uVar1 + 0x100;
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  *(uint *)(DAT_803dc5a8 + 0x1ec) =
       *(uint *)(DAT_803dc5a8 + 0x1ec) & 0xfffffbff |
       (iVar2 - ((uint)(iVar2 == 0) + -uVar1 + 0xff)) * 0x400 & 0x3fc00;
  uVar3 = (*(uint *)(DAT_803dc5a8 + 0x1e4) >> 2 & 0x3ff00) / uVar1;
  uVar5 = (*(uint *)(DAT_803dc5a8 + 0x1e4) >> 10 & 0x3ff) + 1;
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

