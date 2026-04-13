// Function: FUN_80288800
// Entry: 80288800
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x80288cd8) */
/* WARNING: Removing unreachable block (ram,0x802888f4) */

void FUN_80288800(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  byte local_18;
  byte local_17;
  undefined auStack_16 [2];
  uint local_14;
  uint local_10 [2];
  
  if (*(uint *)(param_1 + 8) < 3) {
    FUN_80287e5c(param_1,'\x01');
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
      iVar2 = FUN_80287460(param_1);
      iVar3 = iVar3 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar3);
    return;
  }
  FUN_80287e2c(param_1,0);
  iVar3 = FUN_80287a2c(param_1,(int)auStack_16);
  if (iVar3 == 0) {
    iVar3 = FUN_80287a2c(param_1,(int)&local_17);
  }
  if (local_17 == 0x10) {
LAB_80288904:
    if (iVar3 == 0) {
      FUN_80287a2c(param_1,(int)&local_18);
    }
    if (local_18 == 0) {
      FUN_80287e5c(param_1,'\x01');
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
        iVar2 = FUN_80287460(param_1);
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
        if (local_17 != 0) goto LAB_80288b0c;
        goto LAB_80288904;
      }
    }
    else if (0x11 < local_17) {
LAB_80288b0c:
      FUN_80287e5c(param_1,'\x01');
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
        iVar2 = FUN_80287460(param_1);
        iVar3 = iVar3 + -1;
        if (iVar2 == 0) {
          return;
        }
      } while (0 < iVar3);
      return;
    }
    if (*(int *)(param_1 + 8) != 10) {
      FUN_80287e5c(param_1,'\x01');
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
        iVar2 = FUN_80287460(param_1);
        iVar3 = iVar3 + -1;
        if (iVar2 == 0) {
          return;
        }
      } while (0 < iVar3);
      return;
    }
    if (iVar3 == 0) {
      iVar3 = FUN_802878ac(param_1,(undefined *)local_10);
    }
    if (iVar3 == 0) {
      FUN_802878ac(param_1,(undefined *)&local_14);
    }
    uVar1 = FUN_8028c060();
    if ((uVar1 < local_10[0]) || (local_14 < uVar1)) {
      FUN_80287e5c(param_1,'\x01');
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
        iVar2 = FUN_80287460(param_1);
        iVar3 = iVar3 + -1;
        if (iVar2 == 0) {
          return;
        }
      } while (0 < iVar3);
      return;
    }
  }
  iVar3 = FUN_8028be24();
  if (iVar3 == 0) {
    FUN_80287e5c(param_1,'\x01');
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
      iVar2 = FUN_80287460(param_1);
      iVar3 = iVar3 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar3);
    return;
  }
  FUN_80287e5c(param_1,'\x01');
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
    iVar2 = FUN_80287460(param_1);
    iVar3 = iVar3 + -1;
    if (iVar2 == 0) break;
  } while (0 < iVar3);
  if (iVar2 != 0) {
    return;
  }
  uVar1 = (uint)local_17;
  if (uVar1 == 0x10) {
LAB_80288ce8:
    uVar1 = countLeadingZeros(0x10 - uVar1);
    FUN_8028c0f0((uint)local_18,uVar1 >> 5);
  }
  else {
    if (uVar1 < 0x10) {
      if (uVar1 != 1) {
        if (uVar1 != 0) {
          return;
        }
        goto LAB_80288ce8;
      }
    }
    else if (0x11 < uVar1) {
      return;
    }
    uVar1 = countLeadingZeros(0x11 - uVar1);
    FUN_8028c070(local_10[0],local_14,uVar1 >> 5);
  }
  return;
}

