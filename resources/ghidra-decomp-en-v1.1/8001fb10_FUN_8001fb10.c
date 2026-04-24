// Function: FUN_8001fb10
// Entry: 8001fb10
// Size: 828 bytes

void FUN_8001fb10(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined uVar1;
  bool bVar2;
  undefined *puVar3;
  undefined4 uVar4;
  char cVar6;
  uint uVar5;
  undefined4 extraout_r4;
  undefined4 extraout_r4_00;
  undefined4 extraout_r4_01;
  undefined4 extraout_r4_02;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar9;
  undefined8 uVar10;
  
  uVar9 = 0;
  bVar2 = true;
  puVar3 = FUN_80017400(0);
  uVar1 = puVar3[0x10];
  puVar3[0x10] = 0;
  do {
    uVar9 = uVar9 + 1;
    FUN_80014f6c();
    FUN_80020390();
    FUN_800235b0();
    FUN_8004a9e4();
    uVar10 = FUN_80019940(0xc0,0xc0,0xc0,0xff);
    FUN_800168a8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x33f);
    if (bVar2) {
      uVar7 = 0xff;
      uVar8 = 0xff;
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
      uVar4 = extraout_r4;
    }
    else {
      uVar7 = 0x80;
      uVar8 = 0x80;
      uVar10 = FUN_80019940(0x80,0x80,0x80,0x80);
      uVar4 = extraout_r4_00;
    }
    uVar4 = FUN_8001947c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3cd,uVar4,
                         uVar7,uVar8,in_r7,in_r8,in_r9,in_r10);
    FUN_80015e00(uVar4,0,DAT_803dc088,100);
    if (bVar2) {
      uVar7 = 0x80;
      uVar8 = 0x80;
      uVar10 = FUN_80019940(0x80,0x80,0x80,0x80);
      uVar4 = extraout_r4_01;
    }
    else {
      uVar7 = 0xff;
      uVar8 = 0xff;
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
      uVar4 = extraout_r4_02;
    }
    uVar4 = FUN_8001947c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3cc,uVar4,
                         uVar7,uVar8,in_r7,in_r8,in_r9,in_r10);
    uVar10 = FUN_80015e00(uVar4,0,DAT_803dc08c,100);
    uVar10 = FUN_80019c5c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80014f68();
    FUN_8004a5b8('\0');
    cVar6 = FUN_80014cec(0);
    if ((cVar6 < '\0') || (cVar6 = FUN_80014c44(0), cVar6 < '\0')) {
      bVar2 = true;
    }
    else {
      cVar6 = FUN_80014cec(0);
      if (('\0' < cVar6) || (cVar6 = FUN_80014c44(0), '\0' < cVar6)) {
        bVar2 = false;
      }
    }
    uVar5 = FUN_80014e9c(0);
  } while (((uVar5 & 0x100) == 0) && (uVar9 < 600));
  puVar3[0x10] = uVar1;
  FUN_8004a9e4();
  FUN_8004a5b8('\0');
  FUN_8004a9e4();
  FUN_8004a5b8('\0');
  FUN_8024de40(1);
  FUN_8024dcb8();
  FUN_8024d054();
  FUN_8024d054();
  FUN_8024d054();
  FUN_8024d054();
  if (bVar2) {
    DAT_803dd970 = (uint *)&DAT_8032f2b4;
    FUN_80245f50(1);
    FUN_80259858(*(char *)((int)DAT_803dd970 + 0x19),(byte *)((int)DAT_803dd970 + 0x1a),'\0',
                 (byte *)((int)DAT_803dd970 + 0x32));
    FUN_8024d51c(DAT_803dd970);
    FUN_8024de40(1);
    FUN_8024dcb8();
    uVar4 = 0x340;
  }
  else {
    DAT_803dd970 = (uint *)&DAT_8032f278;
    FUN_80245f50(0);
    FUN_80259858(*(char *)((int)DAT_803dd970 + 0x19),(byte *)((int)DAT_803dd970 + 0x1a),'\x01',
                 (byte *)((int)DAT_803dd970 + 0x32));
    FUN_8024d51c(DAT_803dd970);
    FUN_8024de40(1);
    FUN_8024dcb8();
    uVar4 = 0x341;
  }
  uVar9 = 0;
  do {
    FUN_8024d054();
    uVar9 = uVar9 + 1;
  } while (uVar9 < 100);
  FUN_8024de40(0);
  FUN_8024dcb8();
  FUN_8024d054();
  FUN_8024d054();
  uVar9 = 0;
  do {
    uVar9 = uVar9 + 1;
    FUN_80014f6c();
    FUN_80020390();
    FUN_800235b0();
    FUN_8004a9e4();
    if (uVar9 < 0xff) {
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
    }
    else {
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
    }
    uVar10 = FUN_800168a8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar4);
    uVar10 = FUN_80019c5c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80014f68();
    FUN_8004a5b8('\0');
  } while (uVar9 < 0xf0);
  return;
}

