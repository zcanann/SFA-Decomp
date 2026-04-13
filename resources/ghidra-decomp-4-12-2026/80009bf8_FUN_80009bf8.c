// Function: FUN_80009bf8
// Entry: 80009bf8
// Size: 1424 bytes

undefined4
FUN_80009bf8(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar4;
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar5;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  undefined8 extraout_f1_04;
  undefined8 extraout_f1_05;
  undefined8 extraout_f1_06;
  undefined4 local_10;
  undefined4 local_c;
  
  local_10 = DAT_803df1c8;
  local_c = DAT_803df1cc;
  if (DAT_803dd44c == '\0') {
    DAT_803dd44c = '\x01';
    DAT_803dd478 = 0;
    DAT_803dd474 = 0;
    FUN_80022e00(1);
    if (DAT_803dd450 != '\0') {
      return 1;
    }
    DAT_803dd450 = '\x01';
    FUN_80250838(&DAT_803369f4,10);
    FUN_80251460();
    FUN_8025024c(0);
    FUN_8025001c(0);
    FUN_8028469c(&local_10);
    FUN_802817a8(0x30,0x30,0x18,1,1,0x1000000);
    FUN_802818f8(0x30,0x18);
    bVar4 = FUN_80245dbc();
    if (bVar4) {
      DAT_803dbe48 = 0;
      FUN_802731c8(1);
    }
    else {
      DAT_803dbe48 = 2;
      FUN_802731c8(0);
    }
    DAT_803369dc = 0;
    DAT_803369e8 = FLOAT_803df1d0;
    DAT_803369f0 = FLOAT_803df1d4;
    DAT_803369ec = FLOAT_803df1d8;
    DAT_803369e0 = FLOAT_803df1d8;
    DAT_803369e4 = FLOAT_803df1dc;
    FUN_80285380(-0x7fcc9760);
    FUN_802732c0(0,-0x7fd7acdc,&DAT_803368a0,-1,0,0,0,-1,0);
    iVar1 = FUN_8028190c();
    if (iVar1 == 0) {
      FUN_8007d858();
      return 0xff;
    }
    FUN_802730d4(0x7f,0,0xff);
    FUN_80273134(0x7f,100,'\x01','\x01');
    FUN_8000bdd4();
    uVar5 = FUN_8000d5b4();
    uVar5 = FUN_8000980c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    FUN_80022e00(1);
    DAT_803dd478 = DAT_803dd478 | 8;
    DAT_803dd470 = (int *)FUN_8001599c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      );
    DAT_803dd478 = DAT_803dd478 | 0x10;
    DAT_803dd46c = (int *)FUN_8001599c(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,
                                       param_8);
    DAT_803dd478 = DAT_803dd478 | 0x20;
    DAT_803dd468 = (int *)FUN_8001599c(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,
                                       param_7,param_8);
    uVar5 = extraout_f1_01;
    FUN_80022e00(0);
    DAT_803dd478 = DAT_803dd478 | 0x40;
    DAT_803dd464 = FUN_8001599c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((((DAT_803dd470 == (int *)0x0) || (DAT_803dd46c == (int *)0x0)) ||
        (DAT_803dd468 == (int *)0x0)) || (DAT_803dd464 == 0)) {
      return 0xff;
    }
    param_1 = extraout_f1_02;
    FUN_80022e00(0);
  }
  if ((((DAT_803dd44d == '\0') && ((DAT_803dd474 & 8) != 0)) &&
      (((DAT_803dd474 & 0x10) != 0 && (((DAT_803dd474 & 8) != 0 && ((DAT_803dd474 & 0x20) != 0))))))
     && ((DAT_803dd474 & 0x40) != 0)) {
    FUN_8027be90(DAT_803dd46c,0,DAT_803dd464,DAT_803dd468,DAT_803dd470);
    uVar2 = FUN_800238f8(0);
    uVar5 = FUN_800238c4(DAT_803dd464);
    FUN_800238f8(uVar2);
    DAT_803dd44d = '\x01';
    FUN_80022e00(1);
    DAT_803dd478 = DAT_803dd478 | 0x80;
    DAT_803dd460 = (int *)FUN_8001599c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                      );
    DAT_803dd478 = DAT_803dd478 | 0x100;
    DAT_803dd45c = (int *)FUN_8001599c(extraout_f1_03,param_2,param_3,param_4,param_5,param_6,
                                       param_7,param_8);
    DAT_803dd478 = DAT_803dd478 | 0x200;
    DAT_803dd454 = (int *)FUN_8001599c(extraout_f1_04,param_2,param_3,param_4,param_5,param_6,
                                       param_7,param_8);
    uVar5 = extraout_f1_05;
    FUN_80022e00(0);
    DAT_803dd478 = DAT_803dd478 | 0x400;
    DAT_803dd458 = FUN_8001599c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if ((((DAT_803dd460 == (int *)0x0) || (DAT_803dd45c == (int *)0x0)) ||
        (DAT_803dd454 == (int *)0x0)) || (param_1 = extraout_f1_06, DAT_803dd458 == 0)) {
      return 0xff;
    }
  }
  if (((DAT_803dd44e == '\0') && ((DAT_803dd474 & 0x80) != 0)) &&
     ((((DAT_803dd474 & 0x100) != 0 &&
       (((DAT_803dd474 & 0x80) != 0 && ((DAT_803dd474 & 0x200) != 0)))) &&
      ((DAT_803dd474 & 0x400) != 0)))) {
    iVar1 = 1;
    do {
      iVar3 = FUN_8027be90(DAT_803dd45c,(short)iVar1,DAT_803dd458,DAT_803dd454,DAT_803dd460);
      if (iVar3 == 0) {
        FUN_8007d858();
      }
      iVar1 = iVar1 + 1;
    } while (iVar1 < 0x38);
    uVar2 = FUN_800238f8(0);
    param_1 = FUN_800238c4(DAT_803dd458);
    FUN_800238f8(uVar2);
    DAT_803dd44e = '\x01';
  }
  if (((DAT_803dd44f == '\0') && (DAT_803dd44d != '\0')) && (DAT_803dd44e != '\0')) {
    uVar2 = FUN_8000aeb0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803dd44f = (char)uVar2;
  }
  if ((((DAT_803dd44f == '\0') || (DAT_803dd44d == '\0')) ||
      ((DAT_803dd44e == '\0' || (((DAT_803dd474 & 1) == 0 || ((DAT_803dd474 & 2) == 0)))))) ||
     ((DAT_803dd474 & 4) == 0)) {
    uVar2 = 0;
  }
  else {
    DAT_803dd440 = 0;
    DAT_803dd444 = 0x1f;
    DAT_803dd448 = 0;
    uVar2 = 1;
  }
  return uVar2;
}

