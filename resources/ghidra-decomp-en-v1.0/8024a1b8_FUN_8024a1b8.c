// Function: FUN_8024a1b8
// Entry: 8024a1b8
// Size: 584 bytes

void FUN_8024a1b8(void)

{
  undefined *puVar1;
  int iVar2;
  
  iVar2 = FUN_8024bab0();
  if (iVar2 == 0) {
    DAT_803ddf08 = (undefined *)0x0;
    return;
  }
  if (DAT_803ddf14 != 0) {
    DAT_803ddf08 = (undefined *)0x0;
    DAT_803ddf18 = 1;
    return;
  }
  DAT_803ddf08 = (undefined *)FUN_8024ba10();
  if (DAT_803ddf20 != 0) {
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 0xffffffff;
    puVar1 = DAT_803ddf08;
    DAT_803ddf08 = &DAT_803adf80;
    if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
      (**(code **)(puVar1 + 0x28))(0xffffffff);
    }
    FUN_8024a1b8();
    return;
  }
  DAT_803ddf24 = *(int *)(DAT_803ddf08 + 8);
  switch(DAT_803ddf30) {
  case 1:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 6;
    FUN_80248300(&LAB_8024a0d4);
    break;
  case 2:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 0xb;
    FUN_80248300(&LAB_8024a0d4);
    break;
  case 3:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 4;
    FUN_80248300(&LAB_8024a0d4);
    break;
  case 4:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 5;
    FUN_80248300(&LAB_8024a0d4);
    break;
  case 5:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 0xffffffff;
    FUN_8024bc84(DAT_803ddf34);
    FUN_802483d0(FUN_802493c4);
    break;
  case 6:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 3;
    if (DAT_803ddf24 == 0xd) {
LAB_8024a340:
      FUN_8024b970();
      puVar1 = DAT_803ddf08;
      DAT_803ddf08 = &DAT_803adf80;
      if (*(code **)(puVar1 + 0x28) != (code *)0x0) {
        (**(code **)(puVar1 + 0x28))(0xfffffffc);
      }
      FUN_8024a1b8();
    }
    else {
      if (DAT_803ddf24 < 0xd) {
        if ((DAT_803ddf24 < 6) && (3 < DAT_803ddf24)) goto LAB_8024a340;
      }
      else if (DAT_803ddf24 == 0xf) goto LAB_8024a340;
      FUN_8024b2dc();
      FUN_80240d80(&DAT_803adfb0);
      FUN_80240fdc(&DAT_803adfb0,0x10624dd3,0,((DAT_800000f8 >> 2) / 1000) * 0x47e,&LAB_80249efc);
    }
    break;
  case 7:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 7;
    FUN_80248300(&LAB_8024a0d4);
    break;
  default:
    *(undefined4 *)(DAT_803ddf08 + 0xc) = 1;
    FUN_8024a400(DAT_803ddf08);
    return;
  case 0xbad1abe1:
    break;
  }
  DAT_803ddf30 = 0;
  return;
}

