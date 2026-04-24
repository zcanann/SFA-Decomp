// Function: FUN_8028732c
// Entry: 8028732c
// Size: 308 bytes

/* WARNING: Removing unreachable block (ram,0x80287388) */
/* WARNING: Removing unreachable block (ram,0x8028739c) */
/* WARNING: Removing unreachable block (ram,0x80287394) */

int FUN_8028732c(void)

{
  int iVar1;
  int iVar2;
  
  DAT_803d7578 = 1;
  FUN_80288434();
  iVar1 = FUN_80287288();
  if (iVar1 == 0) {
    iVar1 = FUN_80287ff4();
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80288544();
  }
  if (iVar1 == 0) {
    iVar2 = FUN_8028d924();
    FUN_8028bbd0(DAT_803d8f30);
    if (iVar2 != 0) {
      iVar1 = iVar2;
    }
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80288070();
  }
  if (iVar1 == 0) {
    iVar1 = FUN_8028d184();
  }
  return iVar1;
}

