// Function: FUN_80084ce4
// Entry: 80084ce4
// Size: 220 bytes

void FUN_80084ce4(void)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  
  uVar6 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = -1;
  iVar4 = 0;
  do {
    if (*(short *)(iVar1 + 0x62) <= iVar4) {
      iVar5 = -1;
LAB_80084da8:
      FUN_80286128(iVar5);
      return;
    }
    pcVar3 = (char *)(*(int *)(iVar1 + 0x94) + iVar4 * 4);
    if (*pcVar3 == '\0') {
      iVar5 = (int)*(short *)(pcVar3 + 2);
    }
    else if ((*pcVar3 == '\v') && (0 < *(short *)(pcVar3 + 2))) {
      if (((*(uint *)(pcVar3 + 4) & 0x3f) == 4) &&
         (iVar2 = FUN_80083bf0(*(uint *)(pcVar3 + 4) >> 6 & 0x3ff,iVar1,
                               *(undefined4 *)((int)uVar6 + 0x4c)), iVar2 != 0)) {
        iVar5 = iVar5 + -10;
        if (iVar5 < 0) {
          iVar5 = 0;
        }
        goto LAB_80084da8;
      }
      iVar4 = iVar4 + *(short *)(pcVar3 + 2);
    }
    iVar5 = iVar5 + (uint)(byte)pcVar3[1];
    iVar4 = iVar4 + 1;
  } while( true );
}

