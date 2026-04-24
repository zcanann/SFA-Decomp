// Function: FUN_80020e50
// Entry: 80020e50
// Size: 1456 bytes

void FUN_80020e50(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  uint uVar2;
  undefined4 uVar3;
  char cVar6;
  ushort uVar5;
  int iVar4;
  char cVar7;
  uint uVar9;
  undefined8 uVar10;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 extraout_f1_04;
  char cVar8;
  
  FUN_80286840();
  uVar9 = 0;
  cVar6 = '\0';
  bVar1 = false;
  FUN_80240c5c();
  FUN_80249958();
  FUN_8024cbdc();
  FUN_8024edb8();
  FUN_80242300();
  DAT_803dd970 = &DAT_8032f278;
  DAT_803dd764 = FUN_80245ee0();
  uVar2 = FUN_80245218();
  if ((uVar2 == 0) || (DAT_803dd764 != 1)) {
    FUN_80245f50(0);
  }
  else {
    DAT_803dd970 = &DAT_8032f2b4;
    FUN_80245f50(1);
  }
  FUN_80049ce8();
  FUN_8004a550();
  FUN_80115ff0();
  FUN_80024060();
  FUN_80022e00(1);
  FUN_8004a9b8();
  FUN_80022e00(0);
  FUN_8000fc74();
  FUN_80022e00(1);
  uVar10 = FUN_8001a26c();
  FUN_80022e00(0);
  FUN_800199a8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,3);
  FUN_80022e00(1);
  FUN_800154d8();
  uVar3 = FUN_800238f8(0);
  do {
    FUN_800235b0();
    FUN_80014f6c();
    FUN_80020390();
    uVar10 = FUN_8004a9e4();
    if ((uVar9 & 0xff) == 0) {
      uVar9 = FUN_80009bf8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    if (!bVar1) {
      FUN_80022e00(1);
      uVar10 = FUN_8004b7a4();
    }
    if (((uVar9 & 0xff) != 0) && (cVar6 == '\0')) {
      FUN_80022e00(1);
      cVar6 = FUN_8004937c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar10 = extraout_f1;
    }
    if (!bVar1) {
      FUN_80022e00(1);
      uVar10 = FUN_8006d19c();
    }
    bVar1 = true;
    uVar10 = FUN_80115c80(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80015650(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80019c5c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (*DAT_803dd77c == '\0') {
      cVar8 = '\0';
      cVar7 = '\0';
      uVar5 = FUN_8024e0e0();
      if (uVar5 != 0) {
        uVar2 = FUN_80245218();
        cVar7 = cVar8;
        if (((uVar2 != 0) && (DAT_803dd764 != 1)) && (uVar2 = FUN_80014f14(0), (uVar2 & 0x200) != 0)
           ) {
          cVar7 = '\x01';
        }
        uVar2 = FUN_80245218();
        if ((uVar2 == 0) && ((DAT_803dd764 == 1 || (uVar2 = FUN_80014f14(0), (uVar2 & 0x200) != 0)))
           ) {
          cVar7 = '\x01';
        }
      }
      *DAT_803dd77c = cVar7;
    }
    FUN_8004a5b8('\x01');
  } while (((cVar6 == '\0') || ((uVar9 & 0xff) == 0)) && (DAT_803dd6bd == '\0'));
  while (DAT_803dd6bd != '\0') {
    FUN_800235b0();
    FUN_80014f6c();
    FUN_80020390();
    FUN_8004a9e4();
    FUN_8004a5b8('\x01');
  }
  FUN_800238f8(uVar3);
  FUN_80022e00(1);
  FUN_8004a6e8(5);
  uVar10 = FUN_801380b0();
  uVar10 = FUN_80054f2c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8005cbc8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8002977c();
  uVar10 = FUN_80013f88();
  uVar10 = FUN_8001a23c(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                        (int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_11,param_12,param_13,
                        param_14,param_15,param_16);
  uVar10 = FUN_800199a8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  uVar10 = FUN_8002ea8c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80137d20(extraout_f1_01,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_11,param_12,param_13,param_14,
               param_15,param_16);
  FUN_80069b0c();
  uVar10 = FUN_80062db0();
  FUN_8006fe48(extraout_f1_02,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_11,param_12,param_13,param_14,
               param_15,param_16);
  FUN_80014a24();
  FUN_800298b8();
  FUN_8007e06c();
  FUN_802b76a8();
  FUN_800ea74c();
  uVar10 = FUN_8001bdc8();
  FUN_80059024(extraout_f1_03,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
               (int)((ulonglong)uVar10 >> 0x20),(int)uVar10,param_11,param_12,param_13,param_14,
               param_15,param_16);
  DAT_803dd6e8 = FUN_80013ee8(0);
  DAT_803dd6d0 = FUN_80013ee8(1);
  DAT_803dd714 = FUN_80013ee8(0x12);
  DAT_803dd70c = FUN_80013ee8(0xf);
  DAT_803dd6d4 = FUN_80013ee8(2);
  DAT_803dd6cc = FUN_80013ee8(0x16);
  DAT_803dd6d8 = FUN_80013ee8(5);
  DAT_803dd6dc = FUN_80013ee8(6);
  DAT_803dd6e0 = FUN_80013ee8(7);
  DAT_803dd6e4 = FUN_80013ee8(9);
  DAT_803dd6ec = FUN_80013ee8(3);
  DAT_803dd6f0 = FUN_80013ee8(4);
  DAT_803dd6f4 = DAT_803dd6f0;
  DAT_803dd6f8 = FUN_80013ee8(10);
  DAT_803dd6fc = FUN_80013ee8(0xb);
  DAT_803dd700 = FUN_80013ee8(0xc);
  DAT_803dd704 = FUN_80013ee8(0xd);
  DAT_803dd708 = FUN_80013ee8(0xe);
  DAT_803dd710 = FUN_80013ee8(0x11);
  DAT_803dd718 = FUN_80013ee8(0x13);
  DAT_803dd71c = FUN_80013ee8(0x14);
  DAT_803dd720 = FUN_80013ee8(0x3c);
  DAT_803dd728 = FUN_80013ee8(0x15);
  DAT_803dd72c = (int *)FUN_80013ee8(0x17);
  DAT_803dd734 = FUN_80013ee8(0x18);
  DAT_803dd738 = FUN_80013ee8(0x19);
  DAT_803dd73c = FUN_80013ee8(0x31);
  DAT_803dd740 = FUN_80013ee8(0x2f);
  DAT_803dd724 = FUN_80013ee8(0x3d);
  uVar10 = FUN_80053674(extraout_f1_04,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  uVar10 = FUN_80094040(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_80022e00(0);
  FUN_8001f82c(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,&DAT_803dd75c,0x33,
               param_11,param_12,param_13,param_14,param_15,param_16);
  iVar4 = FUN_8004908c(0x33);
  DAT_803dd758 = (undefined2)(iVar4 >> 1);
  DAT_803dd760 = (**(code **)(*DAT_803dd72c + 0x88))();
  DAT_803dd6bf = 1;
  FUN_80014974(2);
  uVar10 = FUN_8005c964();
  FUN_800208b8(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  FUN_8005d06c(0);
  if (*DAT_803dd77c != '\0') {
    FUN_80244e58(DAT_803dd77c,DAT_803dd77c + 1);
    FUN_8024de40(0);
    FUN_8024dcb8();
    uVar10 = FUN_8024d054();
    FUN_8001fb10(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  FUN_80244e58(0,0);
  FUN_80003494(0x8033cfd8,(uint)DAT_803dd970,0x3c);
  DAT_803dd970 = &DAT_8033cfd8;
  FUN_80049ca8();
  FUN_80049680();
  FUN_8007d858();
  FUN_8028688c();
  return;
}

