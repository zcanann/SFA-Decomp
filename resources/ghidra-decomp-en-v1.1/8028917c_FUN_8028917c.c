// Function: FUN_8028917c
// Entry: 8028917c
// Size: 968 bytes

/* WARNING: Removing unreachable block (ram,0x80289328) */

void FUN_8028917c(int param_1)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  byte local_18;
  undefined uStack_17;
  ushort local_16;
  ushort local_14 [2];
  int aiStack_10 [2];
  
  if (*(uint *)(param_1 + 8) < 7) {
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
    iVar4 = 3;
    do {
      iVar2 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  FUN_80287e2c(param_1,0);
  iVar4 = FUN_80287a2c(param_1,(int)&uStack_17);
  if (iVar4 == 0) {
    iVar4 = FUN_80287a2c(param_1,(int)&local_18);
  }
  if (iVar4 == 0) {
    iVar4 = FUN_80287974(param_1,(undefined *)local_14);
  }
  if (iVar4 == 0) {
    FUN_80287974(param_1,(undefined *)&local_16);
  }
  uVar1 = (uint)local_14[0];
  uVar3 = (uint)local_16;
  if (uVar3 < uVar1) {
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
      *(undefined *)(param_1 + uVar1 + 0x10) = 0x14;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar4 = 3;
    do {
      iVar2 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (local_18 == 2) {
    uVar1 = FUN_8028cab8(uVar1,uVar3,param_1,aiStack_10,0);
  }
  else if (local_18 < 2) {
    if (local_18 == 0) {
      uVar1 = FUN_8028cd64(uVar1,uVar3,param_1,aiStack_10,0);
    }
    else {
      uVar1 = FUN_8028cc28(uVar1,uVar3,param_1,aiStack_10,0);
    }
  }
  else if (local_18 < 4) {
    uVar1 = FUN_8028c680(uVar1,uVar3,param_1,aiStack_10,0);
  }
  else {
    uVar1 = 0x703;
  }
  if (uVar1 == 0) {
    FUN_80287e5c(param_1,'\x01');
    uVar3 = *(uint *)(param_1 + 0xc);
    if (uVar3 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar3 + 1;
      *(undefined *)(param_1 + uVar3 + 0x10) = 0x80;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    uVar3 = *(uint *)(param_1 + 0xc);
    if (uVar3 < 0x880) {
      *(uint *)(param_1 + 0xc) = uVar3 + 1;
      *(undefined *)(param_1 + uVar3 + 0x10) = 0;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
  }
  if (uVar1 == 0) {
    iVar4 = 3;
    do {
      iVar2 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar2 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (uVar1 == 0x703) {
    uVar5 = 0x12;
    goto LAB_80289488;
  }
  if ((int)uVar1 < 0x703) {
    if (uVar1 == 0x701) {
      uVar5 = 0x14;
      goto LAB_80289488;
    }
    if (0x700 < (int)uVar1) {
      uVar5 = 0x15;
      goto LAB_80289488;
    }
    if (uVar1 == 0x302) {
      uVar5 = 2;
      goto LAB_80289488;
    }
  }
  else {
    if (uVar1 == 0x706) {
      uVar5 = 0x20;
      goto LAB_80289488;
    }
    if ((int)uVar1 < 0x706) {
      if ((int)uVar1 < 0x705) {
        uVar5 = 0x21;
      }
      else {
        uVar5 = 0x22;
      }
      goto LAB_80289488;
    }
  }
  uVar5 = 3;
LAB_80289488:
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
    *(undefined *)(param_1 + uVar1 + 0x10) = uVar5;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar4 = 3;
  do {
    iVar2 = FUN_80287460(param_1);
    iVar4 = iVar4 + -1;
    if (iVar2 == 0) {
      return;
    }
  } while (0 < iVar4);
  return;
}

