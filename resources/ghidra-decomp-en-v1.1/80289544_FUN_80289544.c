// Function: FUN_80289544
// Entry: 80289544
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x80289760) */

void FUN_80289544(int param_1)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined uVar5;
  byte local_18;
  undefined uStack_17;
  ushort local_16;
  ushort local_14 [2];
  int aiStack_10 [2];
  
  if (*(int *)(param_1 + 8) != 6) {
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
      *(undefined *)(param_1 + uVar2 + 0x10) = 2;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar4 = 3;
    do {
      iVar3 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
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
    iVar4 = FUN_80287974(param_1,(undefined *)&local_16);
  }
  if (local_16 < local_14[0]) {
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
      *(undefined *)(param_1 + uVar2 + 0x10) = 0x14;
      *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
    }
    iVar4 = 3;
    do {
      iVar3 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (iVar4 == 0) {
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
  }
  bVar1 = local_18 & 7;
  if (bVar1 == 2) {
    uVar2 = FUN_8028cab8((uint)local_14[0],(uint)local_16,param_1,aiStack_10,1);
  }
  else if (bVar1 < 2) {
    if ((local_18 & 7) == 0) {
      uVar2 = FUN_8028cd64((uint)local_14[0],(uint)local_16,param_1,aiStack_10,1);
    }
    else {
      uVar2 = FUN_8028cc28((uint)local_14[0],(uint)local_16,param_1,aiStack_10,1);
    }
  }
  else if (bVar1 < 4) {
    uVar2 = FUN_8028c680((uint)local_14[0],(uint)local_16,param_1,aiStack_10,1);
  }
  else {
    uVar2 = 0x703;
  }
  if (uVar2 == 0) {
    iVar4 = 3;
    do {
      iVar3 = FUN_80287460(param_1);
      iVar4 = iVar4 + -1;
      if (iVar3 == 0) {
        return;
      }
    } while (0 < iVar4);
    return;
  }
  if (uVar2 == 0x704) {
    uVar5 = 0x21;
    goto LAB_80289854;
  }
  if ((int)uVar2 < 0x704) {
    if (uVar2 == 0x702) {
      uVar5 = 0x15;
      goto LAB_80289854;
    }
    if (0x701 < (int)uVar2) {
      uVar5 = 0x12;
      goto LAB_80289854;
    }
    if (0x700 < (int)uVar2) {
      uVar5 = 0x14;
      goto LAB_80289854;
    }
  }
  else {
    if (uVar2 == 0x706) {
      uVar5 = 0x20;
      goto LAB_80289854;
    }
    if ((int)uVar2 < 0x706) {
      uVar5 = 0x22;
      goto LAB_80289854;
    }
  }
  uVar5 = 3;
LAB_80289854:
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
    *(undefined *)(param_1 + uVar2 + 0x10) = uVar5;
    *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
  }
  iVar4 = 3;
  do {
    iVar3 = FUN_80287460(param_1);
    iVar4 = iVar4 + -1;
    if (iVar3 == 0) {
      return;
    }
  } while (0 < iVar4);
  return;
}

