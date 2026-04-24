// Function: FUN_80117668
// Entry: 80117668
// Size: 1280 bytes

void FUN_80117668(undefined4 param_1,undefined4 param_2,undefined4 param_3,uint param_4,uint param_5
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
  FUN_80070310(1,3,1);
  FUN_8025c584(0,1,0,0);
  FUN_8025c688(1);
  FUN_8025c6c8(0);
  FUN_80258b24(2);
  FUN_800702b8(1);
  FUN_8025bff0(7,0,0,7,0);
  FUN_802581e0(2);
  FUN_80257f10(0,1,4,0x3c,0,0x7d);
  FUN_80257f10(1,1,4,0x3c,0,0x7d);
  FUN_8025c2a0(4);
  FUN_8025b6f0(0);
  FUN_8025c0c4(0,1,1,0xff);
  FUN_8025b71c(0);
  FUN_8025ba40(0,0xf,8,0xe,2);
  FUN_8025bb44(0,0,0,0,0,0);
  FUN_8025bac0(0,7,4,6,1);
  FUN_8025bc04(0,1,0,0,0,0);
  FUN_8025be20(0,0xc);
  FUN_8025be8c(0,0x1c);
  FUN_8025bef8(0,0,0);
  FUN_8025c0c4(1,1,2,0xff);
  FUN_8025b71c(1);
  FUN_8025ba40(1,0xf,8,0xe,0);
  FUN_8025bb44(1,0,0,1,0,0);
  FUN_8025bac0(1,7,4,6,0);
  FUN_8025bc04(1,1,0,0,0,0);
  FUN_8025be20(1,0xd);
  FUN_8025be8c(1,0x1d);
  FUN_8025bef8(1,0,0);
  FUN_8025c0c4(2,0,0,0xff);
  FUN_8025b71c(2);
  FUN_8025ba40(2,0xf,8,0xc,0);
  FUN_8025bb44(2,0,0,0,1,0);
  FUN_8025bac0(2,4,7,7,0);
  FUN_8025bc04(2,0,0,0,1,0);
  FUN_8025bef8(2,0,0);
  FUN_8025c0c4(3,0xff,0xff,0xff);
  FUN_8025b71c(3);
  FUN_8025ba40(3,1,0,0xe,0xf);
  FUN_8025bb44(3,0,0,0,1,0);
  FUN_8025bac0(3,7,7,7,7);
  FUN_8025bc04(3,0,0,0,1,0);
  FUN_8025bef8(3,0,0);
  FUN_8025be20(3,0xe);
  local_8c = DAT_803e1d30;
  local_88 = DAT_803e1d34;
  FUN_8025bd38(1,&local_8c);
  local_90 = DAT_803e1d38;
  FUN_8025bdac(0,&local_90);
  local_94 = DAT_803e1d3c;
  FUN_8025bdac(1,&local_94);
  local_98 = DAT_803e1d40;
  FUN_8025bdac(2,&local_98);
  FUN_8025bf50(0,0,1,2,3);
  FUN_8025a310(auStack68,(int)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0,0);
  dVar3 = (double)FLOAT_803e1d44;
  FUN_8025a584(dVar3,dVar3,dVar3,auStack68,0,0,0,0,0);
  FUN_8025a8f0(auStack68,0);
  uVar1 = (int)(short)param_4 >> 1;
  uVar2 = (int)(short)param_5 >> 1;
  FUN_8025a310(auStack100,(int)uVar4,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,0);
  dVar3 = (double)FLOAT_803e1d44;
  FUN_8025a584(dVar3,dVar3,dVar3,auStack100,0,0,0,0,0);
  FUN_8025a8f0(auStack100,1);
  FUN_8025a310(auStack132,param_3,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,0);
  dVar3 = (double)FLOAT_803e1d44;
  FUN_8025a584(dVar3,dVar3,dVar3,auStack132,0,0,0,0,0);
  FUN_8025a8f0(auStack132,2);
  FUN_80286128();
  return;
}

