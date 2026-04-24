// Function: FUN_80288de0
// Entry: 80288de0
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x80288ffc) */

void FUN_80288de0(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  byte local_18;
  undefined uStack23;
  ushort local_16;
  ushort local_14 [2];
  undefined auStack16 [8];
  
  if (*(int *)(param_1 + 8) != 6) {
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
      *(undefined *)(param_1 + uVar2 + 0x10) = 2;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar4 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  FUN_802876c8(param_1,0);
  iVar4 = FUN_802872c8(param_1,&uStack23);
  if (iVar4 == 0) {
    iVar4 = FUN_802872c8(param_1,&local_18);
  }
  if (iVar4 == 0) {
    iVar4 = FUN_80287210(param_1,local_14);
  }
  if (iVar4 == 0) {
    iVar4 = FUN_80287210(param_1,&local_16);
  }
  if (local_16 < local_14[0]) {
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
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x14;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar4 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (iVar4 == 0) {
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
  }
  bVar1 = local_18 & 7;
  if (bVar1 == 2) {
    iVar4 = FUN_8028c354(local_14[0],local_16,param_1,auStack16,1);
  }
  else if (bVar1 < 2) {
    if ((local_18 & 7) == 0) {
      iVar4 = FUN_8028c600(local_14[0],local_16,param_1,auStack16,1);
    }
    else {
      iVar4 = FUN_8028c4c4(local_14[0],local_16,param_1,auStack16,1);
    }
  }
  else if (bVar1 < 4) {
    iVar4 = FUN_8028bf1c(local_14[0],local_16,param_1,auStack16,1);
  }
  else {
    iVar4 = 0x703;
  }
  if (iVar4 == 0) {
    iVar4 = 3;
    do {
      iVar3 = FUN_80286cfc(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (iVar4 == 0x704) {
    uVar5 = 0x21;
    goto LAB_802890f0;
  }
  if (iVar4 < 0x704) {
    if (iVar4 == 0x702) {
      uVar5 = 0x15;
      goto LAB_802890f0;
    }
    if (0x701 < iVar4) {
      uVar5 = 0x12;
      goto LAB_802890f0;
    }
    if (0x700 < iVar4) {
      uVar5 = 0x14;
      goto LAB_802890f0;
    }
  }
  else {
    if (iVar4 == 0x706) {
      uVar5 = 0x20;
      goto LAB_802890f0;
    }
    if (iVar4 < 0x706) {
      uVar5 = 0x22;
      goto LAB_802890f0;
    }
  }
  uVar5 = 3;
LAB_802890f0:
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
    *(undefined *)(param_1 + uVar2 + 0x10) = uVar5;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar4 = 3;
  do {
    iVar3 = FUN_80286cfc(param_1);
    iVar4 = iVar4 + -1;
    if (iVar3 == 0) {
      return;
    }
  } while (0 < iVar4);
  return;
}

