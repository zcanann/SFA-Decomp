// Function: FUN_80015624
// Entry: 80015624
// Size: 556 bytes

void FUN_80015624(void)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = 0xffff;
  if (DAT_803db252 != '\0') {
    DAT_803db252 = '\0';
    DAT_803dc95c = 0;
    FUN_8024b150(&DAT_80339950,FUN_8000d6a4);
  }
  DAT_803dc960 = FUN_8024b36c();
  switch(DAT_803dc960) {
  default:
    if (((DAT_803dc950 != '\0') && (uVar1 = FUN_800430ac(0), (uVar1 & 0xffefffff) == 0)) &&
       ((iVar2 = FUN_80020620(), iVar2 != 1 || (iVar2 = FUN_8024b770(), iVar2 != 0)))) {
      DAT_803dc950 = '\0';
      FUN_800206e8(0);
      FUN_8000b714(0);
    }
    break;
  case 4:
    iVar3 = 0x33d;
    FUN_80014a28();
    if (DAT_803dc950 == '\0') {
      DAT_803dc950 = '\x01';
      FUN_80020628(0xff);
      FUN_800206e8(1);
    }
    break;
  case 5:
    iVar3 = 0x33c;
    FUN_80014a28();
    if (DAT_803dc950 == '\0') {
      DAT_803dc950 = '\x01';
      FUN_80020628(0xff);
      FUN_800206e8(1);
    }
    break;
  case 6:
    iVar3 = 0x33e;
    FUN_80014a28();
    if (DAT_803dc950 == '\0') {
      DAT_803dc950 = '\x01';
      FUN_80020628(0xff);
      FUN_800206e8(1);
    }
    break;
  case 0xb:
    iVar3 = 0x33a;
    FUN_80014a28();
    if (DAT_803dc950 == '\0') {
      DAT_803dc950 = '\x01';
      FUN_80020628(0xff);
      FUN_800206e8(1);
    }
    break;
  case 0xffffffff:
    iVar3 = 0x339;
    FUN_80014a28();
    if (DAT_803dc950 == '\0') {
      DAT_803dc950 = '\x01';
      FUN_80020628(0xff);
      FUN_800206e8(1);
      DAT_803dc951 = 1;
    }
  }
  if (iVar3 != 0xffff) {
    iVar2 = FUN_80019b14();
    FUN_8000b714(1);
    FUN_80019b1c(2,2);
    FUN_80019908(0xff,0xff,0xff,0xff);
    FUN_80016870(iVar3);
    if (iVar2 != 2) {
      FUN_80019b1c(iVar2,2);
    }
  }
  return;
}

