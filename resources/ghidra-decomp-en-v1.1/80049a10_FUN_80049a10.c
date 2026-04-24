// Function: FUN_80049a10
// Entry: 80049a10
// Size: 340 bytes

void FUN_80049a10(void)

{
  bool bVar1;
  short sVar3;
  uint uVar2;
  undefined4 local_98 [3];
  uint auStack_8c [35];
  
  DAT_803dd920 = DAT_803dd920 + 1;
  sVar3 = FUN_80258c18();
  if (sVar3 == (short)(DAT_803dd92a + 1)) {
    bVar1 = DAT_803dd94c == DAT_803dd96c;
    DAT_803dd94c = DAT_803dd96c;
    if (bVar1) {
      DAT_803dd94c = DAT_803dd968;
    }
    DAT_803dd92a = sVar3;
    FUN_8024ddd4(DAT_803dd94c);
    FUN_8024dcb8();
    DAT_803dd929 = 1;
    DAT_803dc228 = DAT_803dd920;
    DAT_803dd920 = 0;
  }
  DAT_803dd92c = DAT_803dd92c + 1;
  if ((DAT_803dd930 != '\0') && (18000 < DAT_803dd92c)) {
    FUN_8004a724();
    FUN_80060cbc();
    FUN_800293b8();
    FUN_80258a94();
    FUN_8025665c((int *)auStack_8c,DAT_803dd950,0x10000);
    FUN_80256744(auStack_8c);
    FUN_80256854(auStack_8c);
    DAT_803dd954 = FUN_802554d0(DAT_803dd958,DAT_803dd964);
    uVar2 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_800137c8((short *)&DAT_80360390,(uint)local_98);
    }
    FUN_802472b0((int *)&DAT_803dd944);
    uVar2 = FUN_8001377c((short *)&DAT_80360390);
    if (uVar2 == 0) {
      FUN_8001378c(-0x7fc9fc70,(uint)local_98);
      FUN_80256c08(local_98[0]);
    }
    else {
      FUN_80256ca0();
      DAT_803dd927 = 0;
    }
    FUN_8004a8f8('\x01');
  }
  return;
}

