// Function: FUN_80117910
// Entry: 80117910
// Size: 1280 bytes

void FUN_80117910(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)

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
  uint auStack_84 [8];
  uint auStack_64 [8];
  uint auStack_44 [17];
  
  uVar4 = FUN_80286840();
  FUN_8007048c(1,3,1);
  FUN_8025cce8(0,1,0,0);
  FUN_8025cdec(1);
  FUN_8025ce2c(0);
  FUN_80259288(2);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80258944(2);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_8025ca04(4);
  FUN_8025be54(0);
  FUN_8025c828(0,1,1,0xff);
  FUN_8025be80(0);
  FUN_8025c1a4(0,0xf,8,0xe,2);
  FUN_8025c2a8(0,0,0,0,0,0);
  FUN_8025c224(0,7,4,6,1);
  FUN_8025c368(0,1,0,0,0,0);
  FUN_8025c584(0,0xc);
  FUN_8025c5f0(0,0x1c);
  FUN_8025c65c(0,0,0);
  FUN_8025c828(1,1,2,0xff);
  FUN_8025be80(1);
  FUN_8025c1a4(1,0xf,8,0xe,0);
  FUN_8025c2a8(1,0,0,1,0,0);
  FUN_8025c224(1,7,4,6,0);
  FUN_8025c368(1,1,0,0,0,0);
  FUN_8025c584(1,0xd);
  FUN_8025c5f0(1,0x1d);
  FUN_8025c65c(1,0,0);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025be80(2);
  FUN_8025c1a4(2,0xf,8,0xc,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c224(2,4,7,7,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c828(3,0xff,0xff,0xff);
  FUN_8025be80(3);
  FUN_8025c1a4(3,1,0,0xe,0xf);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c224(3,7,7,7,7);
  FUN_8025c368(3,0,0,0,1,0);
  FUN_8025c65c(3,0,0);
  FUN_8025c584(3,0xe);
  local_8c = DAT_803e29b0;
  local_88 = DAT_803e29b4;
  FUN_8025c49c(1,(short *)&local_8c);
  local_90 = DAT_803e29b8;
  FUN_8025c510(0,(byte *)&local_90);
  local_94 = DAT_803e29bc;
  FUN_8025c510(1,(byte *)&local_94);
  local_98 = DAT_803e29c0;
  FUN_8025c510(2,(byte *)&local_98);
  FUN_8025c6b4(0,0,1,2,3);
  FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0,
               '\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
  FUN_8025b054(auStack_44,0);
  uVar1 = (int)(short)param_4 >> 1;
  uVar2 = (int)(short)param_5 >> 1;
  FUN_8025aa74(auStack_64,(uint)uVar4,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
  FUN_8025b054(auStack_64,1);
  FUN_8025aa74(auStack_84,param_3,uVar1 & 0xffff,uVar2 & 0xffff,1,0,0,'\0');
  dVar3 = (double)FLOAT_803e29c4;
  FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
  FUN_8025b054(auStack_84,2);
  FUN_8028688c();
  return;
}

