// Function: FUN_802885cc
// Entry: 802885cc
// Size: 340 bytes

void FUN_802885cc(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar1 = FUN_8028b6c0();
  if (iVar1 == 0) {
    FUN_802876f8(param_1,1);
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x16;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar1 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar1);
  }
  else {
    FUN_802876f8(param_1,1);
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar2 = *(uint *)(param_1 + 0xc);
    if (uVar2 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar2 + 1;
      *(undefined *)(param_1 + uVar2 + 0x10) = 0;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar1 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) break;
    } while (0 < iVar1);
    if (iVar3 == 0) {
      FUN_8028d318();
    }
  }
  return;
}

