// Function: FUN_8004c928
// Entry: 8004c928
// Size: 1632 bytes

void FUN_8004c928(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)

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
  if ((((DAT_803dd9ea < 0xc) && (DAT_803dd9e9 < 7)) && ((int)DAT_803dda0c < 6)) &&
     (DAT_803dd9f4 < 2)) {
    FUN_80258674(DAT_803dda08,1,4,0x3c,0,0x7d);
    FUN_80258674(DAT_803dda08 + 1,1,4,0x3c,0,0x7d);
    FUN_8025c828(DAT_803dda10,DAT_803dda08 + 1,DAT_803dda0c + 1,0xff);
    FUN_8025be80(DAT_803dda10);
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,2);
    FUN_8025c2a8(DAT_803dda10,0,0,0,0,2);
    FUN_8025c224(DAT_803dda10,7,4,6,1);
    FUN_8025c368(DAT_803dda10,1,0,0,0,2);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    FUN_8025c5f0(DAT_803dda10,DAT_803dd9ec);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c828(DAT_803dda10 + 1,DAT_803dda08 + 1,DAT_803dda0c + 2,0xff);
    FUN_8025be80(DAT_803dda10 + 1);
    FUN_8025c1a4(DAT_803dda10 + 1,0xf,8,0xe,4);
    FUN_8025c2a8(DAT_803dda10 + 1,0,0,1,0,2);
    FUN_8025c224(DAT_803dda10 + 1,7,4,6,2);
    FUN_8025c368(DAT_803dda10 + 1,1,0,0,0,2);
    FUN_8025c584(DAT_803dda10 + 1,DAT_803dd9f0 + 1);
    FUN_8025c5f0(DAT_803dda10 + 1,DAT_803dd9ec + 1);
    FUN_8025c65c(DAT_803dda10 + 1,0,0);
    FUN_8025c828(DAT_803dda10 + 2,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025be80(DAT_803dda10 + 2);
    FUN_8025c1a4(DAT_803dda10 + 2,0xf,8,0xc,4);
    FUN_8025c2a8(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 2,4,7,7,2);
    FUN_8025c368(DAT_803dda10 + 2,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 2,0,0);
    FUN_8025c828(DAT_803dda10 + 3,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 3);
    FUN_8025c1a4(DAT_803dda10 + 3,5,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c224(DAT_803dda10 + 3,7,7,7,7);
    FUN_8025c368(DAT_803dda10 + 3,0,0,0,1,2);
    FUN_8025c65c(DAT_803dda10 + 3,0,0);
    FUN_8025c584(DAT_803dda10 + 3,DAT_803dd9f0 + 2);
    FUN_8025c828(DAT_803dda10 + 4,0xff,0xff,0xff);
    FUN_8025be80(DAT_803dda10 + 4);
    FUN_8025c1a4(DAT_803dda10 + 4,0,4,0xe,0xf);
    FUN_8025c2a8(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c224(DAT_803dda10 + 4,7,7,7,0);
    FUN_8025c368(DAT_803dda10 + 4,0,0,0,1,0);
    FUN_8025c65c(DAT_803dda10 + 4,0,0);
    FUN_8025c584(DAT_803dda10 + 4,6);
    DAT_803dd9b0 = 1;
    local_8c = DAT_803df730;
    local_88 = DAT_803df734;
    FUN_8025c49c(1,(short *)&local_8c);
    local_90 = DAT_803df738;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_90);
    local_94 = DAT_803df73c;
    FUN_8025c510(DAT_803dd9f4 + 1,(byte *)&local_94);
    local_98 = DAT_803df740;
    FUN_8025c510(DAT_803dd9f4 + 2,(byte *)&local_98);
    FUN_8025aa74(auStack_44,(uint)((ulonglong)uVar4 >> 0x20),param_4 & 0xffff,param_5 & 0xffff,1,0,0
                 ,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_44,0,0,0,'\0',0);
    FUN_8025b054(auStack_44,DAT_803dda0c);
    uVar2 = (int)(short)param_4 >> 1;
    uVar1 = (int)(short)param_5 >> 1;
    FUN_8025aa74(auStack_64,(uint)uVar4,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_64,0,0,0,'\0',0);
    FUN_8025b054(auStack_64,DAT_803dda0c + 1);
    FUN_8025aa74(auStack_84,param_3,uVar2 & 0xffff,uVar1 & 0xffff,1,0,0,'\0');
    dVar3 = (double)FLOAT_803df74c;
    FUN_8025ace8(dVar3,dVar3,dVar3,auStack_84,0,0,0,'\0',0);
    FUN_8025b054(auStack_84,DAT_803dda0c + 2);
    DAT_803dda10 = DAT_803dda10 + 5;
    DAT_803dda08 = DAT_803dda08 + 2;
    DAT_803dda0c = DAT_803dda0c + 3;
    DAT_803dd9f4 = DAT_803dd9f4 + 3;
    DAT_803dd9f0 = DAT_803dd9f0 + 3;
    DAT_803dd9ec = DAT_803dd9ec + 3;
    DAT_803dd9ea = DAT_803dd9ea + 5;
    DAT_803dd9e9 = DAT_803dd9e9 + 2;
  }
  FUN_8028688c();
  return;
}

