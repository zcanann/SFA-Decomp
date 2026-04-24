// Function: FUN_8004c7ac
// Entry: 8004c7ac
// Size: 1632 bytes

void FUN_8004c7ac(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,uint param_5
                 )

{
  uint uVar1;
  uint uVar2;
  double dVar3;
  undefined8 uVar4;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined auStack132 [32];
  undefined auStack100 [32];
  undefined auStack68 [68];
  
  uVar4 = FUN_802860dc();
  if ((((DAT_803dcd6a < 0xc) && (DAT_803dcd69 < 7)) && (DAT_803dcd8c < 6)) && (DAT_803dcd74 < 2)) {
    FUN_80257f10(DAT_803dcd88,1,4,0x3c,0,0x7d);
    FUN_80257f10(DAT_803dcd88 + 1,1,4,0x3c,0,0x7d);
    FUN_8025c0c4(DAT_803dcd90,DAT_803dcd88 + 1,DAT_803dcd8c + 1,0xff);
    FUN_8025b71c(DAT_803dcd90);
    FUN_8025ba40(DAT_803dcd90,0xf,8,0xe,2);
    FUN_8025bb44(DAT_803dcd90,0,0,0,0,2);
    FUN_8025bac0(DAT_803dcd90,7,4,6,1);
    FUN_8025bc04(DAT_803dcd90,1,0,0,0,2);
    FUN_8025be20(DAT_803dcd90,DAT_803dcd70);
    FUN_8025be8c(DAT_803dcd90,DAT_803dcd6c);
    FUN_8025bef8(DAT_803dcd90,0,0);
    FUN_8025c0c4(DAT_803dcd90 + 1,DAT_803dcd88 + 1,DAT_803dcd8c + 2,0xff);
    FUN_8025b71c(DAT_803dcd90 + 1);
    FUN_8025ba40(DAT_803dcd90 + 1,0xf,8,0xe,4);
    FUN_8025bb44(DAT_803dcd90 + 1,0,0,1,0,2);
    FUN_8025bac0(DAT_803dcd90 + 1,7,4,6,2);
    FUN_8025bc04(DAT_803dcd90 + 1,1,0,0,0,2);
    FUN_8025be20(DAT_803dcd90 + 1,DAT_803dcd70 + 1);
    FUN_8025be8c(DAT_803dcd90 + 1,DAT_803dcd6c + 1);
    FUN_8025bef8(DAT_803dcd90 + 1,0,0);
    FUN_8025c0c4(DAT_803dcd90 + 2,DAT_803dcd88,DAT_803dcd8c,0xff);
    FUN_8025b71c(DAT_803dcd90 + 2);
    FUN_8025ba40(DAT_803dcd90 + 2,0xf,8,0xc,4);
    FUN_8025bb44(DAT_803dcd90 + 2,0,0,0,1,2);
    FUN_8025bac0(DAT_803dcd90 + 2,4,7,7,2);
    FUN_8025bc04(DAT_803dcd90 + 2,0,0,0,1,2);
    FUN_8025bef8(DAT_803dcd90 + 2,0,0);
    FUN_8025c0c4(DAT_803dcd90 + 3,0xff,0xff,0xff);
    FUN_8025b71c(DAT_803dcd90 + 3);
    FUN_8025ba40(DAT_803dcd90 + 3,5,4,0xe,0xf);
    FUN_8025bb44(DAT_803dcd90 + 3,0,0,0,1,2);
    FUN_8025bac0(DAT_803dcd90 + 3,7,7,7,7);
    FUN_8025bc04(DAT_803dcd90 + 3,0,0,0,1,2);
    FUN_8025bef8(DAT_803dcd90 + 3,0,0);
    FUN_8025be20(DAT_803dcd90 + 3,DAT_803dcd70 + 2);
    FUN_8025c0c4(DAT_803dcd90 + 4,0xff,0xff,0xff);
    FUN_8025b71c(DAT_803dcd90 + 4);
    FUN_8025ba40(DAT_803dcd90 + 4,0,4,0xe,0xf);
    FUN_8025bb44(DAT_803dcd90 + 4,0,0,0,1,0);
    FUN_8025bac0(DAT_803dcd90 + 4,7,7,7,0);
    FUN_8025bc04(DAT_803dcd90 + 4,0,0,0,1,0);
    FUN_8025bef8(DAT_803dcd90 + 4,0,0);
    FUN_8025be20(DAT_803dcd90 + 4,6);
    DAT_803dcd30 = 1;
    local_8c = DAT_803deab0;
    local_88 = DAT_803deab4;
    FUN_8025bd38(1,&local_8c);
    local_90 = DAT_803deab8;
    FUN_8025bdac(DAT_803dcd74,&local_90);
    local_94 = DAT_803deabc;
    FUN_8025bdac(DAT_803dcd74 + 1,&local_94);
    local_98 = DAT_803deac0;
    FUN_8025bdac(DAT_803dcd74 + 2,&local_98);
    FUN_8025a310(auStack68,(int)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0,0
                );
    dVar3 = (double)FLOAT_803deacc;
    FUN_8025a584(dVar3,dVar3,dVar3,auStack68,0,0,0,0,0);
    FUN_8025a8f0(auStack68,DAT_803dcd8c);
    uVar2 = (int)(short)param_4 >> 1;
    uVar1 = (int)(short)param_5 >> 1;
    FUN_8025a310(auStack100,(int)uVar4,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,0);
    dVar3 = (double)FLOAT_803deacc;
    FUN_8025a584(dVar3,dVar3,dVar3,auStack100,0,0,0,0,0);
    FUN_8025a8f0(auStack100,DAT_803dcd8c + 1);
    FUN_8025a310(auStack132,param_3,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,0);
    dVar3 = (double)FLOAT_803deacc;
    FUN_8025a584(dVar3,dVar3,dVar3,auStack132,0,0,0,0,0);
    FUN_8025a8f0(auStack132,DAT_803dcd8c + 2);
    DAT_803dcd90 = DAT_803dcd90 + 5;
    DAT_803dcd88 = DAT_803dcd88 + 2;
    DAT_803dcd8c = DAT_803dcd8c + 3;
    DAT_803dcd74 = DAT_803dcd74 + 3;
    DAT_803dcd70 = DAT_803dcd70 + 3;
    DAT_803dcd6c = DAT_803dcd6c + 3;
    DAT_803dcd6a = DAT_803dcd6a + 5;
    DAT_803dcd69 = DAT_803dcd69 + 2;
  }
  FUN_80286128();
  return;
}

