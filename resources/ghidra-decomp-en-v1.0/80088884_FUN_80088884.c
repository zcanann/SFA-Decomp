// Function: FUN_80088884
// Entry: 80088884
// Size: 592 bytes

void FUN_80088884(void)

{
  char cVar3;
  uint uVar1;
  byte bVar4;
  int iVar2;
  
  cVar3 = (**(code **)(*DAT_803dca58 + 0x24))(0);
  uVar1 = FUN_8001ffb4(0x2ba);
  uVar1 = uVar1 & 0xff;
  if (cVar3 != DAT_803dd16c) {
    DAT_803dd16c = cVar3;
    if (cVar3 == '\0') {
      uVar1 = uVar1 + 1;
      if ((uVar1 & 0xff) == 0x1c) {
        uVar1 = 0;
      }
      FUN_800200e8(0x2ba,uVar1 & 0xff);
    }
    if (DAT_803dd140 != 0) {
      DAT_803dd140 = DAT_803dd140 | 0x10;
    }
  }
  if ((DAT_803dd140 & 0x10) != 0) {
    bVar4 = DAT_803dd140 & 0xef;
    if (((DAT_803dd130 != 0) && ((DAT_803dd140 & 2) != 0)) &&
       (DAT_803dd140 = bVar4, iVar2 = FUN_8001ffb4(0x3ac), bVar4 = DAT_803dd140, iVar2 == 0)) {
      if ((DAT_803dd140 & 0x20) == 0) {
        FUN_80008cbc(0,0,*(undefined2 *)(DAT_803dd130 + (uVar1 & 0xff) * 2),0);
        bVar4 = DAT_803dd140;
      }
      else {
        FUN_80008b74(0,0,*(undefined2 *)(DAT_803dd130 + (uVar1 & 0xff) * 2),0);
        bVar4 = DAT_803dd140;
      }
    }
    DAT_803dd140 = bVar4;
    if ((DAT_803dd13c != 0) && ((DAT_803dd140 & 4) != 0)) {
      if ((DAT_803dd140 & 0x20) == 0) {
        FUN_80008cbc(0,0,*(undefined2 *)(DAT_803dd13c + (uVar1 & 0xff) * 2),0);
      }
      else {
        FUN_80008b74(0,0,*(undefined2 *)(DAT_803dd13c + (uVar1 & 0xff) * 2),0);
      }
    }
    if (((DAT_803dd138 != 0) && ((DAT_803dd140 & 1) != 0)) &&
       (iVar2 = FUN_8001ffb4(0x3ab), iVar2 == 0)) {
      if ((DAT_803dd140 & 0x20) == 0) {
        FUN_80008cbc(0,0,*(undefined2 *)(DAT_803dd138 + (uVar1 & 0xff) * 2),0);
      }
      else {
        FUN_80008b74(0,0,*(undefined2 *)(DAT_803dd138 + (uVar1 & 0xff) * 2),0);
      }
    }
    FUN_80088ad4(uVar1);
    DAT_803dd140 = DAT_803dd140 & 0xdf;
  }
  return;
}

