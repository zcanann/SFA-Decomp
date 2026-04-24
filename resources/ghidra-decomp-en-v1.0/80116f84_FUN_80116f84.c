// Function: FUN_80116f84
// Entry: 80116f84
// Size: 904 bytes

void FUN_80116f84(void)

{
  int iVar1;
  
  DAT_803dd61a = (*(byte *)(DAT_803dd498 + 0x21) & 0x80) == 0;
  if (0xfd < DAT_803db424) {
    FUN_8007d960(0);
  }
  FUN_80019970(0x15);
  DAT_803dd650 = 0;
  DAT_803dd651 = 0;
  iVar1 = FUN_80014930();
  if (iVar1 != 3) {
    (**(code **)(*DAT_803dcaa0 + 4))(&DAT_8031a214,4,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  }
  else {
    (**(code **)(*DAT_803dcaa0 + 4))(&DAT_8031a1d8,1,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  }
  DAT_803dd652 = iVar1 != 3;
  (**(code **)(*DAT_803dcaa0 + 0x18))(DAT_803dd614);
  FUN_801368a4(0);
  iVar1 = FUN_80014930();
  if ((((iVar1 == 0xd) || (iVar1 = FUN_80014930(), iVar1 == 7)) ||
      (iVar1 = FUN_80014930(), iVar1 == 6)) || (iVar1 = FUN_80014930(), iVar1 == 5)) {
    (**(code **)(*DAT_803dca4c + 0xc))(0x23,5);
  }
  else {
    FUN_80009a94(0xf);
    (**(code **)(*DAT_803dca4c + 0xc))(0x3c,1);
  }
  FUN_80130478();
  if (DAT_803dd614 == '\0') {
    DAT_8031a22a = DAT_8031a22a & 0xbfff;
  }
  else {
    DAT_8031a22a = DAT_8031a22a | 0x4000;
  }
  if (DAT_803dd614 == '\x01') {
    DAT_8031a266 = DAT_8031a266 & 0xbfff;
  }
  else {
    DAT_8031a266 = DAT_8031a266 | 0x4000;
  }
  if (DAT_803dd614 == '\x02') {
    DAT_8031a2a2 = DAT_8031a2a2 & 0xbfff;
  }
  else {
    DAT_8031a2a2 = DAT_8031a2a2 | 0x4000;
  }
  if (DAT_803dd614 == '\x03') {
    DAT_8031a2de = DAT_8031a2de & 0xbfff;
  }
  else {
    DAT_8031a2de = DAT_8031a2de | 0x4000;
  }
  (**(code **)(*DAT_803dcaa0 + 0x2c))(&DAT_8031a214);
  DAT_803dd619 = 0;
  DAT_803dd64d = 0;
  DAT_803dd64c = 1;
  DAT_803dd648 = 0x3c;
  DAT_803dd680 = 0;
  if ((DAT_803dd61a == '\0') || ((DAT_803dd610 != 0 && (DAT_803dd610 != 4)))) {
    FUN_80135820((double)FLOAT_803e1d10,(double)FLOAT_803e1d18);
    DAT_803dd64f = 0;
    FUN_80117b68(0,1);
  }
  else {
    FUN_80116224();
    FUN_80135820((double)FLOAT_803e1d10,(double)FLOAT_803e1d18);
    DAT_803dd64f = 1;
    FUN_80117b68(0,0);
    FUN_80009a28(0,10,1,0,0);
    DAT_803dd616 = 0;
  }
  FUN_8005cea8(0);
  FUN_8005cdf8(0);
  DAT_803dd64e = 0;
  FUN_800887f8(0);
  FUN_8001467c();
  FUN_8000b694(0);
  DAT_803dd698 = 0;
  return;
}

