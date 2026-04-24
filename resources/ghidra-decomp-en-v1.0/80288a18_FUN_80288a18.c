// Function: FUN_80288a18
// Entry: 80288a18
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x80288bc4) */

void FUN_80288a18(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined uVar4;
  byte local_18;
  undefined uStack23;
  ushort local_16;
  ushort local_14 [2];
  undefined auStack16 [8];
  
  if (*(uint *)(param_1 + 8) < 7) {
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
    return;
  }
  FUN_802876c8(param_1,0);
  iVar3 = FUN_802872c8(param_1,&uStack23);
  if (iVar3 == 0) {
    iVar3 = FUN_802872c8(param_1,&local_18);
  }
  if (iVar3 == 0) {
    iVar3 = FUN_80287210(param_1,local_14);
  }
  if (iVar3 == 0) {
    FUN_80287210(param_1,&local_16);
  }
  if (local_16 < local_14[0]) {
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
      *(undefined *)(param_1 + uVar1 + 0x10) = 0x14;
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
    return;
  }
  if (local_18 == 2) {
    iVar3 = FUN_8028c354(local_14[0],local_16,param_1,auStack16,0);
  }
  else if (local_18 < 2) {
    if (local_18 == 0) {
      iVar3 = FUN_8028c600(local_14[0],local_16,param_1,auStack16,0);
    }
    else {
      iVar3 = FUN_8028c4c4(local_14[0],local_16,param_1,auStack16,0);
    }
  }
  else if (local_18 < 4) {
    iVar3 = FUN_8028bf1c(local_14[0],local_16,param_1,auStack16,0);
  }
  else {
    iVar3 = 0x703;
  }
  if (iVar3 == 0) {
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
    return;
  }
  if (iVar3 == 0x703) {
    uVar4 = 0x12;
    goto LAB_80288d24;
  }
  if (iVar3 < 0x703) {
    if (iVar3 == 0x701) {
      uVar4 = 0x14;
      goto LAB_80288d24;
    }
    if (0x700 < iVar3) {
      uVar4 = 0x15;
      goto LAB_80288d24;
    }
    if (iVar3 == 0x302) {
      uVar4 = 2;
      goto LAB_80288d24;
    }
  }
  else {
    if (iVar3 == 0x706) {
      uVar4 = 0x20;
      goto LAB_80288d24;
    }
    if (iVar3 < 0x706) {
      if (iVar3 < 0x705) {
        uVar4 = 0x21;
      }
      else {
        uVar4 = 0x22;
      }
      goto LAB_80288d24;
    }
  }
  uVar4 = 3;
LAB_80288d24:
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
    *(undefined *)(param_1 + uVar1 + 0x10) = uVar4;
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
  return;
}

