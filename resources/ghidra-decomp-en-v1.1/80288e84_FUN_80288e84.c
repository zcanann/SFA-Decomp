// Function: FUN_80288e84
// Entry: 80288e84
// Size: 760 bytes

void FUN_80288e84(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined uVar4;
  byte local_18;
  undefined auStack_17 [3];
  uint local_14;
  uint local_10 [2];
  
  if (*(int *)(param_1 + 8) == 10) {
    FUN_80287e2c(param_1,0);
    iVar3 = FUN_80287a2c(param_1,(int)auStack_17);
    if (iVar3 == 0) {
      iVar3 = FUN_80287a2c(param_1,(int)&local_18);
    }
    if (iVar3 == 0) {
      iVar3 = FUN_802878ac(param_1,(undefined *)local_10);
    }
    if (iVar3 == 0) {
      iVar3 = FUN_802878ac(param_1,(undefined *)&local_14);
    }
    if (local_14 < local_10[0]) {
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
        *(undefined *)(param_1 + uVar1 + 0x10) = 0x13;
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
    }
    else {
      if (iVar3 == 0) {
        iVar3 = FUN_8028be34((uint)local_18,local_10[0],local_14);
      }
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
          *(undefined *)(param_1 + uVar1 + 0x10) = 0;
          *(int *)(param_1 + 8) = *(int *)(param_1 + 8) + 1;
        }
      }
      if (iVar3 == 0) {
        iVar3 = 3;
        do {
          iVar2 = FUN_80287460(param_1);
          iVar3 = iVar3 + -1;
          if (iVar2 == 0) {
            return;
          }
        } while (0 < iVar3);
      }
      else {
        if (iVar3 == 0x703) {
          uVar4 = 0x12;
        }
        else {
          uVar4 = 3;
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
          *(undefined *)(param_1 + uVar1 + 0x10) = uVar4;
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
      }
    }
  }
  else {
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
  }
  return;
}

