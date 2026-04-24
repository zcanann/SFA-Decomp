// Function: FUN_801af568
// Entry: 801af568
// Size: 372 bytes

void FUN_801af568(int param_1)

{
  char cVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == 'H') {
    iVar2 = FUN_8001ffb4(0xe1e);
    if (iVar2 == 0) {
      iVar2 = FUN_8001ffb4(0xb72);
      if (iVar2 == 0) {
        iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(0);
        if (iVar2 == 0) {
          if (*(int *)(iVar3 + 8) != 0x33) {
            *(undefined4 *)(iVar3 + 8) = 0x33;
            FUN_8000a518(0x33,1);
          }
        }
        else if (*(int *)(iVar3 + 8) != 0x2d) {
          *(undefined4 *)(iVar3 + 8) = 0x2d;
          FUN_8000a518(0x2d,1);
        }
      }
      else if (*(int *)(iVar3 + 8) != 0x95) {
        *(undefined4 *)(iVar3 + 8) = 0x95;
        FUN_8000a518(0x95,1);
      }
    }
    FUN_801d7ed4(iVar3 + 0xc,1,0xffffffff,0xffffffff,0xe1e,0x36);
  }
  else if ((cVar1 < 'H') && ('F' < cVar1)) {
    iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(0);
    if (iVar2 == 0) {
      if (*(int *)(iVar3 + 8) != 0x33) {
        *(undefined4 *)(iVar3 + 8) = 0x33;
        FUN_8000a518(0x33,1);
      }
    }
    else if (*(int *)(iVar3 + 8) != 0x2d) {
      *(undefined4 *)(iVar3 + 8) = 0x2d;
      FUN_8000a518(0x2d,1);
    }
  }
  return;
}

