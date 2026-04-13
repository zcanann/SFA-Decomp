// Function: FUN_80118714
// Entry: 80118714
// Size: 944 bytes

void FUN_80118714(void)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  bool bVar4;
  
  if (DAT_803de2e4 != (code *)0x0) {
    (*DAT_803de2e4)();
  }
  iVar3 = -1;
  if (DAT_803a6a58 == 0) {
    return;
  }
  if (DAT_803a6a5c != '\x02') {
    return;
  }
  if ((DAT_803a6a60 != 0) || (DAT_803a6a64 != 0)) {
    DAT_803a6a5c = 5;
    DAT_803a6a5d = 5;
    return;
  }
  if ((DAT_803a6a84 == 0 && DAT_803a6a80 == 0) &&
     ((DAT_803a6a5d == '\0' || (DAT_803a6a5d == '\x04')))) {
    DAT_803a6a5d = '\x02';
  }
  bVar4 = 0xfffffffe < DAT_803a6a84;
  DAT_803a6a84 = DAT_803a6a84 + 1;
  DAT_803a6a80 = DAT_803a6a80 + (uint)bVar4;
  if ((DAT_803a6a5d != '\0') && (DAT_803a6a5d != '\x04')) {
    iVar2 = FUN_801185cc();
    if (iVar2 != 0) {
      if (DAT_803a6a5f == '\0') {
        iVar3 = FUN_801199cc(0);
      }
      else {
        iVar2 = DAT_803a6aa4 - DAT_803a6aa8;
        if ((iVar2 < 2) && (iVar3 = FUN_801199cc(0), iVar2 < DAT_803a6a90)) {
          DAT_803a6a90 = DAT_803a6a90 + -1;
        }
      }
    }
    goto LAB_80118964;
  }
  if ((DAT_803a6a5e & 2) == 0) {
    if ((DAT_803a6a5e & 4) == 0) {
      bVar4 = true;
    }
    else {
      uVar1 = FUN_8024df24();
      if (uVar1 != 1) goto LAB_80118864;
      bVar4 = true;
    }
  }
  else {
    uVar1 = FUN_8024df24();
    if (uVar1 == 0) {
      bVar4 = true;
    }
    else {
LAB_80118864:
      bVar4 = false;
    }
  }
  if (bVar4) {
    if (DAT_803a6a5f == '\0') {
      iVar3 = FUN_801199cc(0);
      DAT_803a6a5d = '\x02';
    }
    else {
      iVar2 = DAT_803a6aa4 - DAT_803a6aa8;
      if (iVar2 < 2) {
        iVar3 = FUN_801199cc(0);
        if (iVar2 < DAT_803a6a90) {
          DAT_803a6a90 = DAT_803a6a90 + -1;
        }
      }
      else {
        DAT_803a6a5d = '\x02';
      }
    }
  }
  else {
    DAT_803a6a84 = -1;
    DAT_803a6a80 = -1;
  }
LAB_80118964:
  iVar2 = DAT_803a6aac;
  if (((iVar3 != 0) && (iVar3 != -1)) &&
     (DAT_803a6aa4 = *(int *)(iVar3 + 0xc), iVar2 = iVar3, DAT_803a6aac != 0)) {
    FUN_80244758((int *)&DAT_803a692c,DAT_803a6aac,0);
  }
  DAT_803a6aac = iVar2;
  if ((DAT_803a6a5e & 1) == 0) {
    if (DAT_803a6a5f == '\0') {
      if (((DAT_803a6aa4 + DAT_803a6a78) -
           ((uint)(DAT_803a6aa4 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 == DAT_803a6a10 - 1)
         && (iVar3 == 0)) {
        DAT_803a6a5d = '\x03';
        DAT_803a6a5c = '\x03';
      }
    }
    else if ((((DAT_803a6aa8 + DAT_803a6a78) -
               ((uint)(DAT_803a6aa8 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
               DAT_803a6a10 - 1) && (DAT_803a6ab0 == 0)) &&
            (((DAT_803a6aa4 + DAT_803a6a78) -
              ((uint)(DAT_803a6aa4 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 ==
              DAT_803a6a10 - 1 && (iVar3 == 0)))) {
      DAT_803a6a5d = '\x03';
      DAT_803a6a5c = '\x03';
    }
  }
  else if ((DAT_803a6aa4 + DAT_803a6a78) -
           ((uint)(DAT_803a6aa4 + DAT_803a6a78) / DAT_803a6a10) * DAT_803a6a10 == DAT_803a6a10 - 1)
  {
    DAT_803de300 = 1;
  }
  return;
}

