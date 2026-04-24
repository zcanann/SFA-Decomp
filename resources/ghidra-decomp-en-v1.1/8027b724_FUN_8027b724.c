// Function: FUN_8027b724
// Entry: 8027b724
// Size: 172 bytes

void FUN_8027b724(uint param_1)

{
  uint uVar1;
  int iVar2;
  
  if (((param_1 != 0xffffffff) &&
      (uVar1 = (uint)(byte)(&DAT_803cc7f8)[param_1 & 0xff], uVar1 != 0xff)) &&
     (iVar2 = uVar1 * 0x24, (uint)(ushort)(&DAT_803cbf0a)[uVar1 * 0x12] == (param_1 >> 8 & 0xffff)))
  {
    if (DAT_803cc83c != (code *)0x0) {
      (*DAT_803cc83c)(2,iVar2 + -0x7fc340f8);
    }
    (&DAT_803cbef8)[iVar2] = 0;
    (&DAT_803cc7f8)[(byte)(&DAT_803cbefb)[iVar2]] = 0xff;
  }
  return;
}

