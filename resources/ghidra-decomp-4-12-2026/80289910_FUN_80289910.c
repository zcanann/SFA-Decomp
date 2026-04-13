// Function: FUN_80289910
// Entry: 80289910
// Size: 1056 bytes

void FUN_80289910(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined uVar4;
  byte local_818;
  undefined uStack_817;
  ushort local_816;
  uint local_814;
  uint local_810;
  undefined auStack_80c [2052];
  
  if (*(uint *)(param_1 + 8) < 9) {
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
  else {
    FUN_80287e2c(param_1,0);
    iVar3 = FUN_80287a2c(param_1,(int)&uStack_817);
    if (iVar3 == 0) {
      iVar3 = FUN_80287a2c(param_1,(int)&local_818);
    }
    if (iVar3 == 0) {
      iVar3 = FUN_80287974(param_1,(undefined *)&local_816);
    }
    if (iVar3 == 0) {
      iVar3 = FUN_802878ac(param_1,(undefined *)&local_810);
    }
    if ((local_818 & 2) == 0) {
      uVar1 = (uint)local_816;
      if ((*(int *)(param_1 + 8) == uVar1 + 8) && (uVar1 < 0x801)) {
        if (iVar3 == 0) {
          local_814 = uVar1;
          iVar3 = FUN_80287cfc(param_1,(int)auStack_80c,uVar1);
          if (iVar3 == 0) {
            iVar3 = FUN_8028ce58((int)auStack_80c,local_810,(int *)&local_814,local_818 >> 3 & 1 ^ 1
                                 ,0);
          }
          local_816 = (ushort)local_814;
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
          iVar3 = FUN_80287ca8(param_1,local_816);
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
          switch(iVar3) {
          case 0x700:
            uVar4 = 0x13;
            break;
          default:
            uVar4 = 3;
            break;
          case 0x702:
            uVar4 = 0x15;
            break;
          case 0x704:
            uVar4 = 0x21;
            break;
          case 0x705:
            uVar4 = 0x22;
            break;
          case 0x706:
            uVar4 = 0x20;
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
    }
  }
  return;
}

