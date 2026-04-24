// Function: FUN_8028855c
// Entry: 8028855c
// Size: 420 bytes

void FUN_8028855c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined local_18;
  char local_17 [15];
  
  local_17[1] = 0;
  local_17[0] = '\0';
  local_18 = 0;
  FUN_80287e2c(param_1,0);
  iVar1 = FUN_80287a2c(param_1,(int)(local_17 + 1));
  if (iVar1 == 0) {
    iVar1 = FUN_80287a2c(param_1,(int)local_17);
  }
  if (iVar1 == 0) {
    iVar1 = FUN_80287a2c(param_1,(int)&local_18);
  }
  if (iVar1 == 0) {
    if (local_17[0] == '\x01') {
      FUN_8028dabc(local_18);
    }
  }
  else {
    FUN_80287e5c(param_1,'\x01');
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
      iVar3 = FUN_80287460(param_1);
      iVar1 = iVar1 + -1;
      if (iVar3 == 0) break;
    } while (0 < iVar1);
  }
  FUN_80287e5c(param_1,'\x01');
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
    iVar3 = FUN_80287460(param_1);
    iVar1 = iVar1 + -1;
    if (iVar3 == 0) {
      return;
    }
  } while (0 < iVar1);
  return;
}

