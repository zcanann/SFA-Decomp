// Function: FUN_80287f9c
// Entry: 80287f9c
// Size: 256 bytes

void FUN_80287f9c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined uVar4;
  
  iVar1 = FUN_8028b698();
  if (iVar1 == 0x704) {
    uVar4 = 0x21;
    goto LAB_80288004;
  }
  if (iVar1 < 0x704) {
    if (iVar1 == 0) {
      uVar4 = 0;
      goto LAB_80288004;
    }
  }
  else {
    if (iVar1 == 0x706) {
      uVar4 = 0x20;
      goto LAB_80288004;
    }
    if (iVar1 < 0x706) {
      uVar4 = 0x22;
      goto LAB_80288004;
    }
  }
  uVar4 = 1;
LAB_80288004:
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
    *(undefined *)(param_1 + uVar2 + 0x10) = uVar4;
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

