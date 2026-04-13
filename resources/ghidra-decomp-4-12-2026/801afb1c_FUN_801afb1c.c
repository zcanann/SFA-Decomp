// Function: FUN_801afb1c
// Entry: 801afb1c
// Size: 372 bytes

void FUN_801afb1c(int param_1)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  cVar1 = *(char *)(param_1 + 0xac);
  if (cVar1 == 'H') {
    uVar3 = FUN_80020078(0xe1e);
    if (uVar3 == 0) {
      uVar3 = FUN_80020078(0xb72);
      if (uVar3 == 0) {
        iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
        if (iVar2 == 0) {
          if (*(int *)(iVar4 + 8) != 0x33) {
            *(undefined4 *)(iVar4 + 8) = 0x33;
            FUN_8000a538((int *)0x33,1);
          }
        }
        else if (*(int *)(iVar4 + 8) != 0x2d) {
          *(undefined4 *)(iVar4 + 8) = 0x2d;
          FUN_8000a538((int *)0x2d,1);
        }
      }
      else if (*(int *)(iVar4 + 8) != 0x95) {
        *(undefined4 *)(iVar4 + 8) = 0x95;
        FUN_8000a538((int *)0x95,1);
      }
    }
    FUN_801d84c4(iVar4 + 0xc,1,-1,-1,0xe1e,(int *)0x36);
  }
  else if ((cVar1 < 'H') && ('F' < cVar1)) {
    iVar2 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
    if (iVar2 == 0) {
      if (*(int *)(iVar4 + 8) != 0x33) {
        *(undefined4 *)(iVar4 + 8) = 0x33;
        FUN_8000a538((int *)0x33,1);
      }
    }
    else if (*(int *)(iVar4 + 8) != 0x2d) {
      *(undefined4 *)(iVar4 + 8) = 0x2d;
      FUN_8000a538((int *)0x2d,1);
    }
  }
  return;
}

