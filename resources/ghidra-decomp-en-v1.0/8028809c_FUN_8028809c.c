// Function: FUN_8028809c
// Entry: 8028809c
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x80288574) */
/* WARNING: Removing unreachable block (ram,0x80288190) */

void FUN_8028809c(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  char local_18;
  byte local_17;
  undefined auStack22 [2];
  uint local_14;
  uint local_10 [2];
  
  if (*(uint *)(param_1 + 8) < 3) {
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
  iVar3 = FUN_802872c8(param_1,auStack22);
  if (iVar3 == 0) {
    iVar3 = FUN_802872c8(param_1,&local_17);
  }
  if (local_17 == 0x10) {
LAB_802881a0:
    if (iVar3 == 0) {
      FUN_802872c8(param_1,&local_18);
    }
    if (local_18 == '\0') {
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
        *(undefined *)(param_1 + uVar1 + 0x10) = 0x11;
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
  }
  else {
    if (local_17 < 0x10) {
      if (local_17 != 1) {
        if (local_17 != 0) goto LAB_802883a8;
        goto LAB_802881a0;
      }
    }
    else if (0x11 < local_17) {
LAB_802883a8:
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
        *(undefined *)(param_1 + uVar1 + 0x10) = 0x12;
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
    if (*(int *)(param_1 + 8) != 10) {
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
    if (iVar3 == 0) {
      iVar3 = FUN_80287148(param_1,local_10);
    }
    if (iVar3 == 0) {
      FUN_80287148(param_1,&local_14);
    }
    uVar1 = FUN_8028b8fc();
    if ((uVar1 < local_10[0]) || (local_14 < uVar1)) {
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
        *(undefined *)(param_1 + uVar1 + 0x10) = 0x11;
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
  }
  iVar3 = FUN_8028b6c0();
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
      *(undefined *)(param_1 + uVar1 + 0x10) = 0x16;
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
  iVar3 = 3;
  do {
    iVar2 = FUN_80286cfc(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) break;
  } while (0 < iVar3);
  if (iVar2 != 0) {
    return;
  }
  uVar1 = (uint)local_17;
  if (uVar1 == 0x10) {
LAB_80288584:
    uVar1 = countLeadingZeros(0x10 - uVar1);
    FUN_8028b98c(local_18,uVar1 >> 5);
  }
  else {
    if (uVar1 < 0x10) {
      if (uVar1 != 1) {
        if (uVar1 != 0) {
          return;
        }
        goto LAB_80288584;
      }
    }
    else if (0x11 < uVar1) {
      return;
    }
    uVar1 = countLeadingZeros(0x11 - uVar1);
    FUN_8028b90c(local_10[0],local_14,uVar1 >> 5);
  }
  return;
}

