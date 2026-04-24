// Function: FUN_8002cc9c
// Entry: 8002cc9c
// Size: 620 bytes

void FUN_8002cc9c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  
  if ((*(ushort *)(param_9 + 0xb0) & 0x40) != 0) {
    return;
  }
  FUN_8000da9c(param_9);
  uVar5 = FUN_8000b7dc(param_9,0x7f);
  if ((*(ushort *)(param_9 + 0xb0) & 0x10) != 0) {
    iVar2 = 0;
    piVar1 = DAT_803dd808;
    iVar3 = DAT_803dd804;
    if (0 < DAT_803dd804) {
      do {
        if (*piVar1 == param_9) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (iVar2 < DAT_803dd804) {
      DAT_803dd804 = DAT_803dd804 + -1;
      iVar3 = iVar2 << 2;
      for (; iVar2 < DAT_803dd804; iVar2 = iVar2 + 1) {
        *(undefined4 *)((int)DAT_803dd808 + iVar3) = ((undefined4 *)((int)DAT_803dd808 + iVar3))[1];
        iVar3 = iVar3 + 4;
      }
    }
    else {
      uVar5 = FUN_8007d858();
    }
    if ((*(ushort *)(param_9 + 0xb0) & 0x10) != 0) {
      uVar5 = FUN_80013abc((short *)&DAT_803dd7fc,param_9);
    }
    DAT_803dd844 = 0;
  }
  iVar3 = 0;
  if (0 < DAT_803dd814) {
    if ((8 < DAT_803dd814) && (uVar4 = DAT_803dd814 - 1U >> 3, 0 < DAT_803dd814 + -8)) {
      do {
        iVar3 = iVar3 + 8;
        uVar4 = uVar4 - 1;
      } while (uVar4 != 0);
    }
    iVar2 = DAT_803dd814 - iVar3;
    if (iVar3 < DAT_803dd814) {
      do {
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
  }
  *(ushort *)(param_9 + 0xb0) = *(ushort *)(param_9 + 0xb0) | 0x40;
  if (*(char *)(param_9 + 0xea) != '\0') {
    iVar2 = 0;
    piVar1 = DAT_803dd810;
    iVar3 = DAT_803dd80c;
    if (0 < DAT_803dd80c) {
      do {
        if (*piVar1 == param_9) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    if (iVar2 != DAT_803dd80c) {
      return;
    }
    if (DAT_803dd80c < 0x18) {
      DAT_803dd810[DAT_803dd80c] = param_9;
      DAT_803dd80c = DAT_803dd80c + 1;
      return;
    }
  }
  if (param_9 != 0) {
    uVar5 = FUN_8007d858();
  }
  if (DAT_803dc0a8 == 2) {
    iVar2 = DAT_803dd814;
    if ((DAT_803dd814 != 0) &&
       (iVar2 = 0, piVar1 = DAT_803dd818, iVar3 = DAT_803dd814, 0 < DAT_803dd814)) {
      do {
        if (*piVar1 == param_9) break;
        piVar1 = piVar1 + 1;
        iVar2 = iVar2 + 1;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    iVar3 = DAT_803dd814;
    if (iVar2 == DAT_803dd814) {
      DAT_803dd818[DAT_803dd814] = param_9;
      iVar3 = DAT_803dd814 + 1;
      if (DAT_803dd814 + 1 == 400) {
        iVar3 = DAT_803dd814;
      }
    }
  }
  else {
    countLeadingZeros(DAT_803dc0a8);
    FUN_8002bf60(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    iVar3 = DAT_803dd814;
  }
  DAT_803dd814 = iVar3;
  return;
}

