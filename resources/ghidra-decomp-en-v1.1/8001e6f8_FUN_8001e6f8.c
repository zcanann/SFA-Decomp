// Function: FUN_8001e6f8
// Entry: 8001e6f8
// Size: 704 bytes

void FUN_8001e6f8(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  char *pcVar6;
  
  uVar4 = 0;
  iVar5 = 0;
  pcVar6 = &DAT_8033cac0;
  do {
    if (*pcVar6 != '\0') {
      if (*(int *)(pcVar6 + 8) == 0) {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          iVar3 = 2;
        }
        else {
          iVar3 = 1;
        }
        if (uVar1 == 0) {
          iVar2 = 0;
        }
        else {
          iVar2 = 2;
        }
        FUN_8025a608(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(uint *)(pcVar6 + 0xc),uVar1,iVar2,iVar3);
      }
      else if (*(int *)(pcVar6 + 8) == 2) {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          iVar3 = 2;
        }
        else {
          iVar3 = 1;
        }
        FUN_8025a608(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(uint *)(pcVar6 + 0xc),uVar1,0,iVar3);
      }
      else {
        uVar1 = *(uint *)(pcVar6 + 4);
        if (uVar1 == 0) {
          iVar3 = 2;
        }
        else {
          iVar3 = 0;
        }
        FUN_8025a608(iVar5,(-uVar1 | uVar1) >> 0x1f,0,*(uint *)(pcVar6 + 0xc),uVar1,0,iVar3);
      }
      uVar4 = uVar4 | 1 << iVar5 & 0xffU;
    }
    pcVar6 = pcVar6 + 0x10;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 6);
  if (((uVar4 & 1) == 0) || ((uVar4 & 4) != 0)) {
    if (((uVar4 & 1) == 0) && ((uVar4 & 4) != 0)) {
      FUN_8025a608(0,0,0,0,0,0,2);
    }
  }
  else {
    FUN_8025a608(2,0,0,0,0,0,2);
  }
  if (((uVar4 & 2) == 0) || ((uVar4 & 8) != 0)) {
    if (((uVar4 & 2) == 0) && ((uVar4 & 8) != 0)) {
      FUN_8025a608(1,0,0,0,0,0,2);
    }
  }
  else {
    FUN_8025a608(3,0,0,0,0,0,2);
  }
  if ((uVar4 & 0x2a) == 0) {
    if ((uVar4 & 0x15) == 0) {
      FUN_8025a608(4,0,0,0,0,0,2);
      FUN_8025a608(5,0,0,0,0,0,2);
      FUN_8025a5bc(0);
    }
    else {
      FUN_8025a608(5,0,0,0,0,0,2);
      FUN_8025a5bc(1);
    }
  }
  else {
    FUN_8025a5bc(2);
  }
  return;
}

