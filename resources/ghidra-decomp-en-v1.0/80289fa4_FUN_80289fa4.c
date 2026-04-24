// Function: FUN_80289fa4
// Entry: 80289fa4
// Size: 728 bytes

void FUN_80289fa4(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined local_18;
  undefined local_17;
  undefined local_16;
  undefined local_15;
  
  if (*(int *)(param_1 + 8) == 1) {
    FUN_802876f8(param_1,1);
    uVar1 = *(uint *)(param_1 + 0xc);
    if (uVar1 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar1 + 1;
      *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar1 = *(uint *)(param_1 + 0xc);
    if (uVar1 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar1 + 1;
      *(undefined *)(param_1 + uVar1 + 0x10) = 0;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar3 = FUN_8028bef4(&local_18);
    if (iVar3 == 0) {
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        iVar3 = 0;
        *(undefined *)(param_1 + uVar1 + 0x10) = local_18;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      else {
        iVar3 = 0x301;
      }
    }
    if (iVar3 == 0) {
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        iVar3 = 0;
        *(undefined *)(param_1 + uVar1 + 0x10) = local_17;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      else {
        iVar3 = 0x301;
      }
    }
    if (iVar3 == 0) {
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        iVar3 = 0;
        *(undefined *)(param_1 + uVar1 + 0x10) = local_16;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      else {
        iVar3 = 0x301;
      }
    }
    if (iVar3 == 0) {
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        iVar3 = 0;
        *(undefined *)(param_1 + uVar1 + 0x10) = local_15;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      else {
        iVar3 = 0x301;
      }
    }
    if (iVar3 == 0) {
      iVar3 = 3;
      do {
        iVar2 = FUN_80286cfc(param_1);
        iVar3 = iVar3 + -1;
        if (iVar2 == 0) {
          return;
        }
      } while (0 < iVar3);
    }
    else {
      FUN_802876f8(param_1,1);
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      uVar1 = *(uint *)(param_1 + 0xc);
      if (uVar1 < 0x880) {
        *(uint *)(param_1 + 0xc) = uVar1 + 1;
        *(undefined *)(param_1 + uVar1 + 0x10) = 3;
        *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
      }
      iVar3 = 3;
      do {
        iVar2 = FUN_80286cfc(param_1);
        iVar3 = iVar3 + -1;
        if (iVar2 == 0) {
          return;
        }
      } while (0 < iVar3);
    }
  }
  else {
    FUN_802876f8(param_1,1);
    uVar1 = *(uint *)(param_1 + 0xc);
    if (uVar1 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar1 + 1;
      *(undefined *)(param_1 + uVar1 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar1 = *(uint *)(param_1 + 0xc);
    if (uVar1 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar1 + 1;
      *(undefined *)(param_1 + uVar1 + 0x10) = 2;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar3 = 3;
    do {
      iVar2 = FUN_80286cfc(param_1);
      iVar3 = iVar3 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar3);
  }
  return;
}

