// Function: FUN_8025854c
// Entry: 8025854c
// Size: 136 bytes

void FUN_8025854c(int param_1,int param_2,int param_3,int param_4)

{
  uint uVar1;
  int iVar2;
  ushort uVar3;
  
  uVar3 = 1;
  if ((param_1 != 1) && (param_1 != 3)) {
    uVar3 = 0;
  }
  iVar2 = countLeadingZeros(3 - param_1);
  uVar1 = countLeadingZeros(2 - param_1);
  *(ushort *)(DAT_803de0b0 + 2) =
       (*(ushort *)(DAT_803de0b0 + 2) & 0xf7fc | uVar3 | (ushort)(iVar2 << 6) & 0xf800 |
       (ushort)(uVar1 >> 4) & 0xfffe) & 0x81f | (ushort)(param_4 << 0xc) | (ushort)(param_2 << 8) |
       (ushort)(param_3 << 5);
  return;
}

