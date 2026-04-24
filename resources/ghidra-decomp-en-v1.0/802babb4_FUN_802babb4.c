// Function: FUN_802babb4
// Entry: 802babb4
// Size: 268 bytes

/* WARNING: Removing unreachable block (ram,0x802babec) */

undefined4 FUN_802babb4(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar3 + 0xa8c);
  if (bVar1 == 3) {
    return 8;
  }
  if (bVar1 < 3) {
    if (bVar1 == 1) {
      iVar3 = FUN_8001ffb4(0x16f);
      if (iVar3 != 0) {
        return 8;
      }
      iVar3 = FUN_8001ffb4(0x28);
      if (iVar3 != 0) {
        return 7;
      }
      iVar3 = FUN_8001ffb4(0x27);
      if (iVar3 != 0) {
        return 7;
      }
      return 6;
    }
    if (bVar1 == 0) {
      iVar2 = FUN_8001ffb4(0xf3);
      if (iVar2 != 0) {
        *(byte *)(iVar3 + 0xa8e) = *(byte *)(iVar3 + 0xa8e) | 0x20;
      }
      return 2;
    }
  }
  else {
    if (bVar1 == 5) {
      return 3;
    }
    if (bVar1 < 5) {
      iVar3 = FUN_8001ffb4(0x1db);
      if (iVar3 != 0) {
        return 8;
      }
      return 6;
    }
  }
  return 8;
}

