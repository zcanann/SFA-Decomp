// Function: FUN_8027afc0
// Entry: 8027afc0
// Size: 172 bytes

void FUN_8027afc0(uint param_1)

{
  uint uVar1;
  int iVar2;
  
  if (((param_1 != 0xffffffff) &&
      (uVar1 = (uint)(byte)(&DAT_803cbb98)[param_1 & 0xff], uVar1 != 0xff)) &&
     (iVar2 = uVar1 * 0x24, (uint)(ushort)(&DAT_803cb2aa)[uVar1 * 0x12] == (param_1 >> 8 & 0xffff)))
  {
    if (DAT_803cbbdc != (code *)0x0) {
      (*DAT_803cbbdc)(2,iVar2 + -0x7fc34d58);
    }
    (&DAT_803cb298)[iVar2] = 0;
    (&DAT_803cbb98)[(byte)(&DAT_803cb29b)[iVar2]] = 0xff;
  }
  return;
}

