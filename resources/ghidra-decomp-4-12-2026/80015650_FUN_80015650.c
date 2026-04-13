// Function: FUN_80015650
// Entry: 80015650
// Size: 568 bytes

undefined4
FUN_80015650(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar4 = 0xffff;
  if (DAT_803dbeb2 != '\0') {
    DAT_803dbeb2 = '\0';
    DAT_803dd5dc = 0;
    FUN_8024b8b4((undefined4 *)&DAT_8033a5b0,FUN_8000d6c4);
  }
  DAT_803dd5e0 = FUN_8024bad0();
  switch(DAT_803dd5e0) {
  default:
    if (((DAT_803dd5d0 != '\0') && (uVar1 = FUN_800431a4(), (uVar1 & 0xffefffff) == 0)) &&
       ((iVar2 = FUN_800206e4(), iVar2 != 1 || (iVar2 = FUN_8024bed4(), iVar2 != 0)))) {
      DAT_803dd5d0 = '\0';
      FUN_800207ac(0);
      FUN_8000b734(0);
    }
    break;
  case 4:
    iVar4 = 0x33d;
    FUN_80014a54();
    if (DAT_803dd5d0 == '\0') {
      DAT_803dd5d0 = '\x01';
      FUN_800206ec(0xff);
      FUN_800207ac(1);
    }
    break;
  case 5:
    iVar4 = 0x33c;
    FUN_80014a54();
    if (DAT_803dd5d0 == '\0') {
      DAT_803dd5d0 = '\x01';
      FUN_800206ec(0xff);
      FUN_800207ac(1);
    }
    break;
  case 6:
    iVar4 = 0x33e;
    FUN_80014a54();
    if (DAT_803dd5d0 == '\0') {
      DAT_803dd5d0 = '\x01';
      FUN_800206ec(0xff);
      FUN_800207ac(1);
    }
    break;
  case 0xb:
    iVar4 = 0x33a;
    FUN_80014a54();
    if (DAT_803dd5d0 == '\0') {
      DAT_803dd5d0 = '\x01';
      FUN_800206ec(0xff);
      FUN_800207ac(1);
    }
    break;
  case -1:
    iVar4 = 0x339;
    FUN_80014a54();
    if (DAT_803dd5d0 == '\0') {
      DAT_803dd5d0 = '\x01';
      FUN_800206ec(0xff);
      FUN_800207ac(1);
      DAT_803dd5d1 = 1;
    }
  }
  if (iVar4 == 0xffff) {
    uVar3 = 0;
  }
  else {
    iVar2 = FUN_80019b4c();
    FUN_8000b734(1);
    FUN_80019b54(2,2);
    uVar5 = FUN_80019940(0xff,0xff,0xff,0xff);
    FUN_800168a8(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4);
    if (iVar2 != 2) {
      FUN_80019b54(iVar2,2);
    }
    uVar3 = 1;
  }
  return uVar3;
}

