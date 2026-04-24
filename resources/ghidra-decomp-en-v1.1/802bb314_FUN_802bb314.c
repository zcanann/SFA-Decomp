// Function: FUN_802bb314
// Entry: 802bb314
// Size: 268 bytes

/* WARNING: Removing unreachable block (ram,0x802bb34c) */

undefined4 FUN_802bb314(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  bVar1 = *(byte *)(iVar3 + 0xa8c);
  if (bVar1 == 3) {
    return 8;
  }
  if (bVar1 < 3) {
    if (bVar1 == 1) {
      uVar2 = FUN_80020078(0x16f);
      if (uVar2 != 0) {
        return 8;
      }
      uVar2 = FUN_80020078(0x28);
      if (uVar2 != 0) {
        return 7;
      }
      uVar2 = FUN_80020078(0x27);
      if (uVar2 != 0) {
        return 7;
      }
      return 6;
    }
    if (bVar1 == 0) {
      uVar2 = FUN_80020078(0xf3);
      if (uVar2 != 0) {
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
      uVar2 = FUN_80020078(0x1db);
      if (uVar2 != 0) {
        return 8;
      }
      return 6;
    }
  }
  return 8;
}

