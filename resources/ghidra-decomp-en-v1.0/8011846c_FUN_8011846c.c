// Function: FUN_8011846c
// Entry: 8011846c
// Size: 944 bytes

void FUN_8011846c(void)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  
  if (DAT_803dd664 != (code *)0x0) {
    (*DAT_803dd664)();
  }
  iVar2 = -1;
  if (DAT_803a5df8 == 0) {
    return;
  }
  if (DAT_803a5dfc != '\x02') {
    return;
  }
  if ((DAT_803a5e00 != 0) || (DAT_803a5e04 != 0)) {
    DAT_803a5dfc = 5;
    DAT_803a5dfd = 5;
    return;
  }
  if (((DAT_803a5e24 | DAT_803a5e20) == 0) && ((DAT_803a5dfd == '\0' || (DAT_803a5dfd == '\x04'))))
  {
    DAT_803a5dfd = '\x02';
  }
  bVar3 = 0xfffffffe < DAT_803a5e24;
  DAT_803a5e24 = DAT_803a5e24 + 1;
  DAT_803a5e20 = DAT_803a5e20 + bVar3;
  if ((DAT_803a5dfd != '\0') && (DAT_803a5dfd != '\x04')) {
    iVar1 = FUN_80118324();
    if (iVar1 != 0) {
      if (DAT_803a5dff == '\0') {
        iVar2 = FUN_80119724(0);
      }
      else {
        iVar1 = DAT_803a5e44 - DAT_803a5e48;
        if ((iVar1 < 2) && (iVar2 = FUN_80119724(0), iVar1 < DAT_803a5e30)) {
          DAT_803a5e30 = DAT_803a5e30 + -1;
        }
      }
    }
    goto LAB_801186bc;
  }
  if ((DAT_803a5dfe & 2) == 0) {
    if ((DAT_803a5dfe & 4) == 0) {
      bVar3 = true;
    }
    else {
      iVar1 = FUN_8024d7c0();
      if (iVar1 != 1) goto LAB_801185bc;
      bVar3 = true;
    }
  }
  else {
    iVar1 = FUN_8024d7c0();
    if (iVar1 == 0) {
      bVar3 = true;
    }
    else {
LAB_801185bc:
      bVar3 = false;
    }
  }
  if (bVar3) {
    if (DAT_803a5dff == '\0') {
      iVar2 = FUN_80119724(0);
      DAT_803a5dfd = '\x02';
    }
    else {
      iVar1 = DAT_803a5e44 - DAT_803a5e48;
      if (iVar1 < 2) {
        iVar2 = FUN_80119724(0);
        if (iVar1 < DAT_803a5e30) {
          DAT_803a5e30 = DAT_803a5e30 + -1;
        }
      }
      else {
        DAT_803a5dfd = '\x02';
      }
    }
  }
  else {
    DAT_803a5e24 = -1;
    DAT_803a5e20 = -1;
  }
LAB_801186bc:
  iVar1 = DAT_803a5e4c;
  if (((iVar2 != 0) && (iVar2 != -1)) &&
     (DAT_803a5e44 = *(int *)(iVar2 + 0xc), iVar1 = iVar2, DAT_803a5e4c != 0)) {
    FUN_80244060(&DAT_803a5ccc,DAT_803a5e4c,0);
  }
  DAT_803a5e4c = iVar1;
  if ((DAT_803a5dfe & 1) == 0) {
    if (DAT_803a5dff == '\0') {
      if (((DAT_803a5e44 + DAT_803a5e18) -
           ((uint)(DAT_803a5e44 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 == DAT_803a5db0 - 1)
         && (iVar2 == 0)) {
        DAT_803a5dfd = '\x03';
        DAT_803a5dfc = '\x03';
      }
    }
    else if ((((DAT_803a5e48 + DAT_803a5e18) -
               ((uint)(DAT_803a5e48 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 ==
               DAT_803a5db0 - 1) && (DAT_803a5e50 == 0)) &&
            (((DAT_803a5e44 + DAT_803a5e18) -
              ((uint)(DAT_803a5e44 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 ==
              DAT_803a5db0 - 1 && (iVar2 == 0)))) {
      DAT_803a5dfd = '\x03';
      DAT_803a5dfc = '\x03';
    }
  }
  else if ((DAT_803a5e44 + DAT_803a5e18) -
           ((uint)(DAT_803a5e44 + DAT_803a5e18) / DAT_803a5db0) * DAT_803a5db0 == DAT_803a5db0 - 1)
  {
    DAT_803dd680 = 1;
  }
  return;
}

