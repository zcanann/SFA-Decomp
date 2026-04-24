// Function: FUN_8028db4c
// Entry: 8028db4c
// Size: 188 bytes

/* WARNING: Removing unreachable block (ram,0x8028dbcc) */

undefined4 FUN_8028db4c(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  undefined4 uVar1;
  char cVar3;
  int iVar2;
  byte bVar4;
  
  cVar3 = FUN_8028daac();
  if ((cVar3 != '\0') && (iVar2 = FUN_8028adac(), iVar2 != 0)) {
    uVar1 = *param_3;
    bVar4 = FUN_8028d0d0();
    *param_3 = uVar1;
    if (bVar4 != 1) {
      if (bVar4 == 0) {
        return 0;
      }
      if (bVar4 < 3) {
        return 2;
      }
    }
  }
  return 1;
}

