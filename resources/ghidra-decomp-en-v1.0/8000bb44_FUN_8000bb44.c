// Function: FUN_8000bb44
// Entry: 8000bb44
// Size: 624 bytes

void FUN_8000bb44(void)

{
  bool bVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  
  piVar2 = &DAT_80336000;
  iVar5 = 0x37;
  do {
    if ((*piVar2 != -1) && (iVar4 = FUN_8027292c(), iVar4 == -1)) {
      *piVar2 = -1;
    }
    piVar2 = piVar2 + 0xe;
    bVar1 = iVar5 != 0;
    iVar5 = iVar5 + -1;
  } while (bVar1);
  iVar5 = FUN_8001ffb4(0xcbb);
  if (iVar5 == 0) {
    iVar5 = FUN_8001ffb4(0xefa);
    if (iVar5 == 0) {
      iVar5 = FUN_8001ffb4(0xefb);
      if (iVar5 == 0) {
        iVar5 = FUN_8001ffb4(0xefd);
        if (iVar5 == 0) {
          iVar5 = FUN_8001ffb4(0xa7f);
          if (iVar5 == 0) {
            iVar5 = FUN_8001ffb4(0xefc);
            if (iVar5 == 0) {
              iVar5 = FUN_8001ffb4(0xefe);
              if (iVar5 == 0) {
                iVar5 = FUN_8001ffb4(0xdcf);
                if (iVar5 == 0) {
                  iVar5 = FUN_8000ae88();
                  if (iVar5 < 0x29) {
                    uVar3 = 0xc;
                  }
                  else {
                    uVar3 = 0;
                  }
                }
                else {
                  uVar3 = 0xb;
                }
              }
              else {
                uVar3 = 0xc;
              }
            }
            else {
              uVar3 = 0xc;
            }
          }
          else {
            uVar3 = 0xc;
          }
        }
        else {
          uVar3 = 0xc;
        }
      }
      else {
        uVar3 = 0xd;
      }
    }
    else {
      uVar3 = 0xc;
    }
  }
  else {
    uVar3 = 0xe;
  }
  if (uVar3 != DAT_803dc838 / 5) {
    piVar2 = &DAT_80336000;
    DAT_803dc838 = (char)uVar3 * '\x05';
    iVar5 = 0x37;
    do {
      if ((*piVar2 != -1) && (*(char *)(piVar2 + 10) == '\0')) {
        FUN_802727a8(*piVar2,0x5b,DAT_803dc838);
      }
      piVar2 = piVar2 + 0xe;
      bVar1 = iVar5 != 0;
      iVar5 = iVar5 + -1;
    } while (bVar1);
  }
  piVar2 = &DAT_80336000;
  iVar5 = 0x37;
  do {
    if ((*piVar2 != -1) && (*(char *)(piVar2 + 1) != '\0')) {
      if (*(char *)((int)piVar2 + 5) != '\0') {
        if ((*(ushort *)(piVar2[6] + 0xb0) & 0x40) == 0) {
          piVar2[3] = *(int *)(piVar2[6] + 0x18);
          piVar2[4] = *(int *)(piVar2[6] + 0x1c);
          piVar2[5] = *(int *)(piVar2[6] + 0x20);
        }
        else {
          *(undefined *)((int)piVar2 + 5) = 0;
        }
      }
      if ((*(char *)((int)piVar2 + 5) != '\0') || (*(char *)(piVar2 + 10) != '\0')) {
        FUN_8000c6c0(piVar2);
      }
    }
    piVar2 = piVar2 + 0xe;
    bVar1 = iVar5 != 0;
    iVar5 = iVar5 + -1;
  } while (bVar1);
  return;
}

