// Function: FUN_8002cbc4
// Entry: 8002cbc4
// Size: 588 bytes

void FUN_8002cbc4(int param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  if ((*(ushort *)(param_1 + 0xb0) & 0x40) != 0) {
    return;
  }
  FUN_8000da7c();
  FUN_8000b7bc(param_1,0x7f);
  if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
    iVar2 = 0;
    piVar1 = DAT_803dcb88;
    iVar3 = DAT_803dcb84;
    if (0 < DAT_803dcb84) {
      do {
        if (*piVar1 == param_1) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (iVar2 < DAT_803dcb84) {
      DAT_803dcb84 = DAT_803dcb84 + -1;
      iVar3 = iVar2 << 2;
      for (; iVar2 < DAT_803dcb84; iVar2 = iVar2 + 1) {
        *(undefined4 *)((int)DAT_803dcb88 + iVar3) = ((undefined4 *)((int)DAT_803dcb88 + iVar3))[1];
        iVar3 = iVar3 + 4;
      }
    }
    else {
      FUN_8007d6dc(s_Tried_to_free_non_existent_objec_802cace0);
    }
    if ((*(ushort *)(param_1 + 0xb0) & 0x10) != 0) {
      FUN_80013a9c(&DAT_803dcb7c,param_1);
    }
    DAT_803dcbc4 = 0;
  }
  iVar3 = 0;
  if (0 < DAT_803dcb94) {
    if ((8 < DAT_803dcb94) && (uVar4 = DAT_803dcb94 - 1U >> 3, 0 < DAT_803dcb94 + -8)) {
      do {
        iVar3 = iVar3 + 8;
        uVar4 = uVar4 - 1;
      } while (uVar4 != 0);
    }
    iVar2 = DAT_803dcb94 - iVar3;
    if (iVar3 < DAT_803dcb94) {
      do {
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x40;
  if (*(char *)(param_1 + 0xea) != '\0') {
    iVar2 = 0;
    piVar1 = DAT_803dcb90;
    iVar3 = DAT_803dcb8c;
    if (0 < DAT_803dcb8c) {
      do {
        if (*piVar1 == param_1) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (iVar2 != DAT_803dcb8c) {
      return;
    }
    if (DAT_803dcb8c < 0x18) {
      DAT_803dcb90[DAT_803dcb8c] = param_1;
      DAT_803dcb8c = DAT_803dcb8c + 1;
      return;
    }
  }
  if (DAT_803db448 == 2) {
    iVar2 = DAT_803dcb94;
    if ((DAT_803dcb94 != 0) &&
       (iVar2 = 0, piVar1 = DAT_803dcb98, iVar3 = DAT_803dcb94, 0 < DAT_803dcb94)) {
      do {
        if (*piVar1 == param_1) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    iVar3 = DAT_803dcb94;
    if (iVar2 == DAT_803dcb94) {
      DAT_803dcb98[DAT_803dcb94] = param_1;
      iVar3 = DAT_803dcb94 + 1;
      if (DAT_803dcb94 + 1 == 400) {
        iVar3 = DAT_803dcb94;
      }
    }
  }
  else {
    uVar4 = countLeadingZeros(DAT_803db448);
    FUN_8002be88(param_1,uVar4 >> 5);
    iVar3 = DAT_803dcb94;
  }
  DAT_803dcb94 = iVar3;
  return;
}

