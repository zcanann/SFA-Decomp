// Function: FUN_8001e634
// Entry: 8001e634
// Size: 704 bytes

void FUN_8001e634(void)

{
  uint uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  
  uVar4 = 0;
  iVar5 = 0;
  pcVar6 = &DAT_8033be60;
  do {
    if (*pcVar6 != '\0') {
      if (*(int *)(pcVar6 + 8) == 0) {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          uVar3 = 2;
        }
        else {
          uVar3 = 1;
        }
        if (uVar1 == 0) {
          uVar2 = 0;
        }
        else {
          uVar2 = 2;
        }
        FUN_80259ea4(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(undefined4 *)(pcVar6 + 0xc),uVar1,uVar2,
                     uVar3);
      }
      else if (*(int *)(pcVar6 + 8) == 2) {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          uVar3 = 2;
        }
        else {
          uVar3 = 1;
        }
        FUN_80259ea4(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(undefined4 *)(pcVar6 + 0xc),uVar1,0,uVar3);
      }
      else {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          uVar3 = 2;
        }
        else {
          uVar3 = 0;
        }
        FUN_80259ea4(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(undefined4 *)(pcVar6 + 0xc),uVar1,0,uVar3);
      }
      uVar4 = uVar4 | 1 << iVar5 & 0xffU;
    }
    pcVar6 = pcVar6 + 0x10;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 6);
  if (((uVar4 & 1) == 0) || ((uVar4 & 4) != 0)) {
    if (((uVar4 & 1) == 0) && ((uVar4 & 4) != 0)) {
      FUN_80259ea4(0,0,0,0,0,0,2);
    }
  }
  else {
    FUN_80259ea4(2,0,0,0,0,0,2);
  }
  if (((uVar4 & 2) == 0) || ((uVar4 & 8) != 0)) {
    if (((uVar4 & 2) == 0) && ((uVar4 & 8) != 0)) {
      FUN_80259ea4(1,0,0,0,0,0,2);
    }
  }
  else {
    FUN_80259ea4(3,0,0,0,0,0,2);
  }
  if ((uVar4 & 0x2a) == 0) {
    if ((uVar4 & 0x15) == 0) {
      FUN_80259ea4(4,0,0,0,0,0,2);
      FUN_80259ea4(5,0,0,0,0,0,2);
      FUN_80259e58(0);
    }
    else {
      FUN_80259ea4(5,0,0,0,0,0,2);
      FUN_80259e58(1);
    }
  }
  else {
    FUN_80259e58(2);
  }
  return;
}

