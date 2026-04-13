// Function: FUN_8024a91c
// Entry: 8024a91c
// Size: 584 bytes

void FUN_8024a91c(void)

{
  int *piVar1;
  int iVar2;
  
  iVar2 = FUN_8024c214();
  if (iVar2 == 0) {
    DAT_803deb88 = (int *)0x0;
    return;
  }
  if (DAT_803deb94 != 0) {
    DAT_803deb88 = (int *)0x0;
    DAT_803deb98 = 1;
    return;
  }
  DAT_803deb88 = FUN_8024c174();
  if (DAT_803deba0 != 0) {
    DAT_803deb88[3] = -1;
    piVar1 = DAT_803deb88;
    DAT_803deb88 = (int *)&DAT_803aebe0;
    if ((code *)piVar1[10] != (code *)0x0) {
      (*(code *)piVar1[10])(0xffffffff);
    }
    FUN_8024a91c();
    return;
  }
  DAT_803deba4 = DAT_803deb88[2];
  if (DAT_803debb0 == 0) {
    DAT_803deb88[3] = 1;
    FUN_8024ab64((int)DAT_803deb88);
    return;
  }
  switch(DAT_803debb0) {
  case 1:
    DAT_803deb88[3] = 6;
    FUN_80248a64(&LAB_8024a838);
    break;
  case 2:
    DAT_803deb88[3] = 0xb;
    FUN_80248a64(&LAB_8024a838);
    break;
  case 3:
    DAT_803deb88[3] = 4;
    FUN_80248a64(&LAB_8024a838);
    break;
  case 4:
    DAT_803deb88[3] = 5;
    FUN_80248a64(&LAB_8024a838);
    break;
  case 5:
    DAT_803deb88[3] = -1;
    FUN_8024c3e8(DAT_803debb4);
    FUN_80248b34(FUN_80249b28);
    break;
  case 6:
    DAT_803deb88[3] = 3;
    if (DAT_803deba4 == 0xd) {
LAB_8024aaa4:
      FUN_8024c0d4();
      piVar1 = DAT_803deb88;
      DAT_803deb88 = (int *)&DAT_803aebe0;
      if ((code *)piVar1[10] != (code *)0x0) {
        (*(code *)piVar1[10])(0xfffffffc);
      }
      FUN_8024a91c();
    }
    else {
      if (DAT_803deba4 < 0xd) {
        if ((DAT_803deba4 < 6) && (3 < DAT_803deba4)) goto LAB_8024aaa4;
      }
      else if (DAT_803deba4 == 0xf) goto LAB_8024aaa4;
      FUN_8024ba40();
      FUN_80241478((undefined4 *)&DAT_803aec10);
      FUN_802416d4((undefined4 *)&DAT_803aec10,0x10624dd3,0,(DAT_800000f8 / 4000) * 0x47e,
                   &LAB_8024a660);
    }
    break;
  case 7:
    DAT_803deb88[3] = 7;
    FUN_80248a64(&LAB_8024a838);
  }
  DAT_803debb0 = 0;
  return;
}

