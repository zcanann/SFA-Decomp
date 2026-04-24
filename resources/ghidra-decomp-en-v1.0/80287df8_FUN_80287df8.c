// Function: FUN_80287df8
// Entry: 80287df8
// Size: 420 bytes

void FUN_80287df8(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined local_18;
  char local_17;
  undefined local_16 [14];
  
  local_16[0] = 0;
  local_17 = '\0';
  local_18 = 0;
  FUN_802876c8(param_1,0);
  iVar1 = FUN_802872c8(param_1,local_16);
  if (iVar1 == 0) {
    iVar1 = FUN_802872c8(param_1,&local_17);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_802872c8(param_1,&local_18);
  }
  if (iVar1 == 0) {
    if (local_17 == '\x01') {
      FUN_8028d35c(local_18);
    }
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
      *(undefined *)(param_1 + uVar2 + 0x10) = 1;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar1 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) break;
    } while (0 < iVar1);
  }
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
    if (iVar3 == 0) {
      return;
    }
  } while (0 < iVar1);
  return;
}

