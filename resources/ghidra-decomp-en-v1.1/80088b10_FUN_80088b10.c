// Function: FUN_80088b10
// Entry: 80088b10
// Size: 592 bytes

void FUN_80088b10(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar3;
  uint uVar1;
  byte bVar4;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar5;
  
  cVar3 = (**(code **)(*DAT_803dd6d8 + 0x24))(0);
  uVar5 = extraout_f1;
  uVar1 = FUN_80020078(0x2ba);
  uVar1 = uVar1 & 0xff;
  if (cVar3 != DAT_803dddec) {
    DAT_803dddec = cVar3;
    if (cVar3 == '\0') {
      uVar1 = uVar1 + 1;
      if ((uVar1 & 0xff) == 0x1c) {
        uVar1 = 0;
      }
      uVar5 = FUN_800201ac(0x2ba,uVar1 & 0xff);
    }
    if (DAT_803dddc0 != 0) {
      DAT_803dddc0 = DAT_803dddc0 | 0x10;
    }
  }
  if ((DAT_803dddc0 & 0x10) != 0) {
    bVar4 = DAT_803dddc0 & 0xef;
    if (((DAT_803dddb0 != 0) && ((DAT_803dddc0 & 2) != 0)) &&
       (DAT_803dddc0 = bVar4, uVar2 = FUN_80020078(0x3ac), bVar4 = DAT_803dddc0, uVar2 == 0)) {
      if ((DAT_803dddc0 & 0x20) == 0) {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddb0 + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
        bVar4 = DAT_803dddc0;
      }
      else {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddb0 + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
        bVar4 = DAT_803dddc0;
      }
    }
    DAT_803dddc0 = bVar4;
    if ((DAT_803dddbc != 0) && ((DAT_803dddc0 & 4) != 0)) {
      if ((DAT_803dddc0 & 0x20) == 0) {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddbc + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
      }
      else {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddbc + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
      }
    }
    if (((DAT_803dddb8 != 0) && ((DAT_803dddc0 & 1) != 0)) &&
       (uVar2 = FUN_80020078(0x3ab), uVar2 == 0)) {
      if ((DAT_803dddc0 & 0x20) == 0) {
        uVar5 = FUN_80008cbc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddb8 + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
      }
      else {
        uVar5 = FUN_80008b74(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,0,
                             (uint)*(ushort *)(DAT_803dddb8 + (uVar1 & 0xff) * 2),0,in_r7,in_r8,
                             in_r9,in_r10);
      }
    }
    FUN_80088d60(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(byte)uVar1);
    DAT_803dddc0 = DAT_803dddc0 & 0xdf;
  }
  return;
}

