// Function: FUN_800ea200
// Entry: 800ea200
// Size: 56 bytes

ushort FUN_800ea200(void)

{
  int iVar1;
  
  iVar1 = FUN_800e8044();
  return *(ushort *)(&DAT_803119e0 + (uint)*(byte *)(iVar1 + 5) * 2) & 0xff;
}

