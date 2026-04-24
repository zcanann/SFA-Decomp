// Function: FUN_80050558
// Entry: 80050558
// Size: 1232 bytes

void FUN_80050558(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025b71c(DAT_803dcd90);
  FUN_8025d160((int)uVar3,DAT_803dcd80,0);
  FUN_80257f10(DAT_803dcd88,0,0,0,0,DAT_803dcd80);
  if ((param_5 == 0) || (param_5 == 2)) {
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,4);
  }
  else {
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88,DAT_803dcd8c,5);
  }
  if (DAT_803dcd90 == 0) {
    uVar2 = 0xc;
  }
  else {
    uVar2 = 4;
  }
  if (param_3 == 0) {
    if (param_4 == 2) {
      FUN_8025ba40(DAT_803dcd90,0xf,uVar2,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025ba40(DAT_803dcd90,uVar2,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025ba40(DAT_803dcd90,0xf,0xf,8);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025ba40(DAT_803dcd90,0xf,10,8);
    }
    else {
      FUN_8025ba40(DAT_803dcd90,0xf,0xb,8);
    }
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bac0(DAT_803dcd90,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025bb44(DAT_803dcd90,1,0,0,1,2);
      FUN_8025bc04(DAT_803dcd90,1,0,0,1,2);
    }
    else {
      FUN_8025bb44(DAT_803dcd90,0,0,0,1,2);
      FUN_8025bc04(DAT_803dcd90,0,0,0,1,2);
    }
  }
  else if (param_3 == 1) {
    if (param_4 == 2) {
      FUN_8025ba40(DAT_803dcd90,0xf,6,8,0xf);
    }
    else if (param_4 == 3) {
      FUN_8025ba40(DAT_803dcd90,6,0xf,8,0xf);
    }
    else if (param_4 == 1) {
      FUN_8025ba40(DAT_803dcd90,0xf,0xf,8,6);
    }
    else if ((param_5 == 0) || (param_5 == 1)) {
      FUN_8025ba40(DAT_803dcd90,0xf,10,8,6);
    }
    else {
      FUN_8025ba40(DAT_803dcd90,0xf,0xb,8,6);
    }
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025bac0(DAT_803dcd90,7,7,7,7);
    if (param_4 == 1) {
      FUN_8025bb44(DAT_803dcd90,1,0,0,1,3);
      FUN_8025bc04(DAT_803dcd90,1,0,0,1,3);
    }
    else {
      FUN_8025bb44(DAT_803dcd90,0,0,0,1,3);
      FUN_8025bc04(DAT_803dcd90,0,0,0,1,3);
    }
  }
  else {
    DAT_803dcd6b = 1;
    DAT_803dcd30 = 1;
    FUN_8025bf50(1,0,0,0,1);
    FUN_8025bef8(DAT_803dcd90,1,1);
    FUN_8025ba40(DAT_803dcd90,0xf,0xf,0xf,0xc);
    if (param_4 == 3) {
      FUN_8025bac0(DAT_803dcd90,7,5,4,6);
      FUN_8025bc04(DAT_803dcd90,1,0,0,1,0);
    }
    else {
      FUN_8025bac0(DAT_803dcd90,7,5,4,7);
      FUN_8025bc04(DAT_803dcd90,0,0,0,1,0);
    }
    FUN_8025bb44(DAT_803dcd90,0,0,0,1,0);
  }
  if (iVar1 != 0) {
    if (*(char *)(iVar1 + 0x48) == '\0') {
      FUN_8025a8f0(iVar1 + 0x20,DAT_803dcd8c);
    }
    else {
      FUN_8025a748(iVar1 + 0x20,*(undefined4 *)(iVar1 + 0x40));
    }
  }
  DAT_803dcd80 = DAT_803dcd80 + 3;
  DAT_803dcd88 = DAT_803dcd88 + 1;
  DAT_803dcd90 = DAT_803dcd90 + 1;
  DAT_803dcd8c = DAT_803dcd8c + 1;
  DAT_803dcd6a = DAT_803dcd6a + '\x01';
  DAT_803dcd69 = DAT_803dcd69 + '\x01';
  FUN_80286128();
  return;
}

