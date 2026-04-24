// Function: FUN_80049894
// Entry: 80049894
// Size: 340 bytes

void FUN_80049894(void)

{
  bool bVar1;
  short sVar3;
  int iVar2;
  undefined4 local_98 [3];
  undefined auStack140 [140];
  
  DAT_803dcca0 = DAT_803dcca0 + 1;
  sVar3 = FUN_802584b4();
  if (sVar3 == (short)(DAT_803dccaa + 1)) {
    bVar1 = DAT_803dcccc == DAT_803dccec;
    DAT_803dcccc = DAT_803dccec;
    if (bVar1) {
      DAT_803dcccc = DAT_803dcce8;
    }
    DAT_803dccaa = sVar3;
    FUN_8024d670();
    FUN_8024d554();
    DAT_803dcca9 = 1;
    DAT_803db5c8 = DAT_803dcca0;
    DAT_803dcca0 = 0;
  }
  DAT_803dccac = DAT_803dccac + 1;
  if ((DAT_803dccb0 != '\0') && (18000 < DAT_803dccac)) {
    FUN_8004a5a8();
    FUN_80060b40();
    FUN_800292e0();
    FUN_80258330();
    FUN_80255ef8(auStack140,DAT_803dccd0,0x10000);
    FUN_80255fe0(auStack140);
    FUN_802560f0(auStack140);
    DAT_803dccd4 = FUN_80254d6c(DAT_803dccd8,DAT_803dcce4);
    iVar2 = FUN_8001375c(&DAT_8035f730);
    if (iVar2 == 0) {
      FUN_800137a8(&DAT_8035f730,local_98);
    }
    FUN_80246b4c(&DAT_803dccc4);
    iVar2 = FUN_8001375c(&DAT_8035f730);
    if (iVar2 == 0) {
      FUN_8001376c(&DAT_8035f730,local_98);
      FUN_802564a4(local_98[0]);
    }
    else {
      FUN_8025653c();
      DAT_803dcca7 = 0;
    }
    FUN_8004a77c(1);
  }
  return;
}

