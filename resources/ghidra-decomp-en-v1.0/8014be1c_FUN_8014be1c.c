// Function: FUN_8014be1c
// Entry: 8014be1c
// Size: 584 bytes

void FUN_8014be1c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = FUN_802860d8();
  iVar6 = *(int *)(iVar1 + 0xb8);
  iVar5 = *(int *)(iVar1 + 0x4c);
  if (*(int *)(iVar1 + 0xf4) == 0) {
    *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | 0x8000;
    FUN_80003494(iVar6 + 0x2c4,iVar6 + 0x2b8,0xc);
    FUN_80003494(iVar6 + 0x2b8,iVar1 + 0x24,0xc);
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
      switch(*(undefined *)(param_3 + iVar4 + 0x81)) {
      case 1:
        iVar3 = FUN_8002b9ac();
        if (iVar3 != 0) {
          (**(code **)(**(int **)(iVar3 + 0x68) + 0x34))(iVar3,1,iVar1);
          *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) | 0x200000;
          *(int *)(iVar6 + 0x29c) = iVar3;
        }
        break;
      case 2:
        if (*(short *)(iVar1 + 0x46) == 0x7a6) {
          *(undefined2 *)(iVar6 + 0x2b6) = 0x7a5;
        }
        else {
          *(undefined2 *)(iVar6 + 0x2b6) = 0x33;
        }
        break;
      case 3:
        (**(code **)(*DAT_803dca54 + 0x50))(0x49,4,iVar1,0x3c);
        break;
      case 4:
        iVar3 = FUN_8002b9ec();
        if (iVar3 != 0) {
          *(uint *)(iVar6 + 0x2dc) = *(uint *)(iVar6 + 0x2dc) & 0xffdfffff;
          *(int *)(iVar6 + 0x29c) = iVar3;
        }
        break;
      case 6:
        if (*(int *)(iVar6 + 0x36c) != 0) {
          FUN_80026c30(*(int *)(iVar6 + 0x36c),1);
        }
        break;
      case 7:
        if (*(int *)(iVar6 + 0x36c) != 0) {
          FUN_80026c30(*(int *)(iVar6 + 0x36c),0);
        }
      }
    }
    FUN_8014a058(iVar1,iVar6);
    if (*(short *)(iVar1 + 0xb4) == -1) {
      *(uint *)(iVar6 + 0x2e8) = *(uint *)(iVar6 + 0x2e8) & 0xfffffffc;
      FUN_80035f00(iVar1);
      uVar2 = 0;
    }
    else {
      if ((*(uint *)(iVar6 + 0x2dc) & 0x1800) == 0) {
        FUN_8014bc98(iVar1,iVar6);
        FUN_8014b878(iVar1,iVar6);
      }
      if (((*(char *)(iVar5 + 0x2e) == -1) || ((*(uint *)(iVar6 + 0x2dc) & 0x600) == 0)) ||
         ((int)*(char *)(param_3 + 0x57) != (int)*(short *)(iVar1 + 0xb4))) {
        uVar2 = 0;
      }
      else {
        uVar2 = 4;
      }
    }
  }
  else {
    uVar2 = 0;
  }
  FUN_80286124(uVar2);
  return;
}

