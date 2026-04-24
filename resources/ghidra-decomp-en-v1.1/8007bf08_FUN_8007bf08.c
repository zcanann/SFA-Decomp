// Function: FUN_8007bf08
// Entry: 8007bf08
// Size: 1604 bytes

void FUN_8007bf08(int param_1,int param_2)

{
  uint uVar1;
  uint uVar2;
  char cVar3;
  undefined auStack_60 [4];
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  float afStack_40 [13];
  
  FUN_8006c86c(0);
  FUN_8004c460(param_1,1);
  FUN_8004c460(param_2,2);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_8025d8c4((float *)&DAT_80397480,0x55,0);
  FUN_80258674(0,0,0,0,0,0x55);
  FUN_80247a7c((double)FLOAT_803dfbe4,(double)FLOAT_803dfb64,(double)FLOAT_803dfb5c,afStack_40);
  FUN_8025d8c4(afStack_40,0x1e,1);
  FUN_80258674(2,1,4,0x1e,0,0x7d);
  FUN_8025a608(4,0,0,1,0,0,2);
  cVar3 = FUN_8004c3c4();
  if (cVar3 == '\0') {
    (**(code **)(*DAT_803dd6d8 + 0x40))
              (&local_44,(int)&local_44 + 1,(int)&local_44 + 2,auStack_60,auStack_60,auStack_60);
  }
  else {
    local_44._2_2_ = CONCAT11(DAT_803ddc9c._2_1_,(undefined)local_44);
    local_44 = CONCAT22(CONCAT11(DAT_803ddc9c._0_1_,DAT_803ddc9c._1_1_),local_44._2_2_);
  }
  local_4c = DAT_803dc2f0;
  FUN_8025c510(0,(byte *)&local_4c);
  FUN_8025c584(0,0xc);
  local_50 = DAT_803dc2f4;
  FUN_8025c510(1,(byte *)&local_50);
  FUN_8025c584(1,0xd);
  local_54 = DAT_803dc2f8;
  FUN_8025c510(2,(byte *)&local_54);
  FUN_8025c584(2,0xe);
  uVar1 = local_44 >> 0x18;
  uVar2 = local_44 >> 0x10;
  local_44._2_2_ = CONCAT11((char)((int)(local_44 >> 8 & 0xff) >> 2),(undefined)local_44);
  local_44 = CONCAT22(CONCAT11((char)((int)uVar1 >> 2),(char)((int)(uVar2 & 0xff) >> 2)),
                      local_44._2_2_);
  local_58 = local_44;
  FUN_8025c428(1,(byte *)&local_58);
  local_48 = CONCAT13(local_44._0_1_ + -0x40,CONCAT12(local_44._1_1_ + -0x40,local_48._2_2_));
  local_48._2_2_ = CONCAT11(local_44._2_1_ + -0x40,(undefined)local_48);
  local_5c = local_48;
  FUN_8025c428(2,(byte *)&local_5c);
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,(float *)&DAT_8030f5d0,-1);
  FUN_8025b9e8(2,(float *)&DAT_8030f5e8,-1);
  FUN_8025b9e8(3,(float *)&DAT_8030f600,-1);
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8025b94c(1,0,0,7,2,0,0,0,0,1);
  FUN_8025b94c(2,0,0,7,3,0,0,0,0,0);
  FUN_8025be54(1);
  FUN_80258944(3);
  FUN_8025ca04(4);
  FUN_8025a5bc(1);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,8,0xe,2);
  FUN_8025c224(0,7,7,7,5);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c828(1,0,0,8);
  FUN_8025c1a4(1,0xf,8,0xe,0);
  FUN_8025c224(1,7,5,0,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025c1a4(2,0xf,8,0xe,0);
  FUN_8025c224(2,7,7,7,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025be80(3);
  FUN_8025c828(3,2,2,0xff);
  FUN_8025c1a4(3,0,4,9,0xf);
  FUN_8025c224(3,7,7,7,0);
  FUN_8025c65c(3,0,0);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c368(3,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  return;
}

