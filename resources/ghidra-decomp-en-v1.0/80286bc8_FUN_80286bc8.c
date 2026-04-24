// Function: FUN_80286bc8
// Entry: 80286bc8
// Size: 308 bytes

/* WARNING: Removing unreachable block (ram,0x80286c24) */
/* WARNING: Removing unreachable block (ram,0x80286c38) */
/* WARNING: Removing unreachable block (ram,0x80286c30) */

int FUN_80286bc8(void)

{
  int iVar1;
  int iVar2;
  
  DAT_803d6918 = 1;
  FUN_80287cd0();
  iVar1 = FUN_80286b24();
  if (iVar1 == 0) {
    iVar1 = FUN_80287890();
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287de0();
  }
  if (iVar1 == 0) {
    iVar2 = FUN_8028d1c4(0xe100,1,0,&DAT_803d82d0);
    FUN_8028b46c(DAT_803d82d0);
    if (iVar2 != 0) {
      iVar1 = iVar2;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_8028790c();
  }
  if (iVar1 == 0) {
    iVar1 = FUN_8028ca24();
  }
  return iVar1;
}

