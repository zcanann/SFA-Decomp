// Function: FUN_8028d368
// Entry: 8028d368
// Size: 132 bytes

/* WARNING: Removing unreachable block (ram,0x8028d3b4) */

undefined4 FUN_8028d368(undefined4 param_1)

{
  int iVar1;
  byte bVar2;
  
  iVar1 = FUN_8028a648();
  if (iVar1 == 0) {
    return 1;
  }
  bVar2 = FUN_8028c980(0xd3,param_1);
  if (bVar2 != 1) {
    if (bVar2 == 0) {
      return 0;
    }
    if (bVar2 < 3) {
      return 2;
    }
  }
  return 1;
}

