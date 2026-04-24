// Function: FUN_8004a43c
// Entry: 8004a43c
// Size: 304 bytes

undefined4 FUN_8004a43c(char param_1)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 local_28;
  undefined auStack36 [4];
  undefined4 local_20;
  undefined4 local_1c;
  int local_18;
  
  FUN_80070310(1,3,1);
  FUN_8025c6c8(1);
  FUN_802582a0();
  FUN_802563c8(DAT_803dccd4,auStack36,&local_28);
  local_20 = local_28;
  local_1c = 0;
  local_18 = DAT_803dccd0;
  uVar2 = FUN_8024377c();
  FUN_8001381c(&DAT_8035f730,&local_20);
  if (DAT_803dcca7 == '\0') {
    FUN_802564a4(local_28);
    DAT_803dcca7 = '\x01';
  }
  FUN_802437a4(uVar2);
  FUN_802583fc(DAT_803db5ce);
  FUN_80259338(DAT_803dccd0,1);
  FUN_802582a0();
  DAT_803db5ce = DAT_803db5ce + 1;
  bVar1 = DAT_803dccd0 == DAT_803dccec;
  DAT_803dccd0 = DAT_803dccec;
  if (bVar1) {
    DAT_803dccd0 = DAT_803dcce8;
  }
  if (((param_1 != '\0') && (DAT_803db5cc != '\0')) &&
     (DAT_803db5cc = DAT_803db5cc + -1, DAT_803db5cc == '\0')) {
    FUN_8024d6dc(0);
    DAT_803db5cc = '\0';
  }
  return 0;
}

