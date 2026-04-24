// Function: FUN_8007d0f8
// Entry: 8007d0f8
// Size: 1780 bytes

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8007d0f8(void)

{
  char cVar1;
  double dVar2;
  undefined auStack_100 [4];
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  int local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [12];
  float afStack_74 [3];
  undefined4 local_68;
  undefined4 local_58;
  float afStack_44 [7];
  undefined4 local_28;
  
  FUN_8006cc38(&local_f4,&local_f8);
  FUN_8006c86c(0);
  FUN_80258674(0,0,0,0x1e,0,0x7d);
  FUN_8006c760(&local_f0);
  FUN_8004c460(local_f0,1);
  dVar2 = (double)FLOAT_803dfb64;
  FUN_80247a7c(dVar2,dVar2,dVar2,afStack_44);
  local_28 = local_f4;
  FUN_8025d8c4(afStack_44,0x27,1);
  FUN_80258674(1,1,4,0x27,0,0x7d);
  local_bc = FLOAT_803dfb78;
  local_b8 = FLOAT_803dfb5c;
  local_b4 = FLOAT_803dfb5c;
  local_b0 = FLOAT_803dfb5c;
  local_ac = FLOAT_803dfb78;
  local_a8 = FLOAT_803dfb5c;
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_bc,-2);
  FUN_8025b94c(0,0,0,7,1,6,6,0,0,0);
  dVar2 = (double)FLOAT_803dfbc0;
  FUN_80247a7c(dVar2,dVar2,dVar2,afStack_74);
  FUN_8024782c((double)FLOAT_803dfb70,afStack_a4,0x7a);
  FUN_80247618(afStack_a4,afStack_74,afStack_74);
  local_68 = local_f8;
  local_58 = local_f8;
  FUN_8025d8c4(afStack_74,0x2a,1);
  FUN_80258674(2,1,4,0x2a,0,0x7d);
  local_d4 = FLOAT_803dfc04;
  local_d0 = FLOAT_803dfc04;
  local_cc = FLOAT_803dfb5c;
  local_c8 = FLOAT_803dfc08;
  local_c4 = FLOAT_803dfc04;
  local_c0 = FLOAT_803dfb5c;
  FUN_8025bd1c(1,2,1);
  FUN_8025bb48(1,0,0);
  FUN_8025b9e8(2,&local_d4,-4);
  FUN_8025b94c(1,1,0,7,2,0,0,1,0,0);
  cVar1 = FUN_8004c3c4();
  if (cVar1 == '\0') {
    (**(code **)(*DAT_803dd6d8 + 0x40))
              (&DAT_803dc2dc,0x803dc2dd,0x803dc2de,auStack_100,auStack_100,auStack_100);
    _DAT_803dc2dc =
         CONCAT31(CONCAT21(CONCAT11((char)((int)(_DAT_803dc2dc >> 0x18) >> 3),
                                    (char)((int)(_DAT_803dc2dc >> 0x10 & 0xff) >> 3)),
                           (char)((int)(_DAT_803dc2dc >> 8 & 0xff) >> 3)),DAT_803dc2d8);
  }
  else {
    _DAT_803dc2dc =
         CONCAT31(CONCAT21(CONCAT11(DAT_803ddc9c._0_1_,DAT_803ddc9c._1_1_),DAT_803ddc9c._2_1_),0x80)
    ;
  }
  local_fc = _DAT_803dc2dc;
  FUN_8025c510(0,(byte *)&local_fc);
  FUN_8025c5f0(1,0x1c);
  FUN_8025c584(1,0xc);
  FUN_8025be54(2);
  FUN_8025a5bc(1);
  FUN_80258944(4);
  FUN_8025ca04(4);
  FUN_8025c828(0,0xff,0xff,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c828(1,0,0,0xff);
  FUN_8025c1a4(1,0xe,0xf,0xf,8);
  FUN_8025c224(1,7,7,7,6);
  FUN_8025c65c(1,0,0);
  cVar1 = FUN_8004c3c4();
  if (cVar1 == '\0') {
    FUN_8025c2a8(1,0,0,0,1,1);
  }
  else {
    FUN_8025c2a8(1,0,0,3,1,1);
  }
  FUN_8025c368(1,0,0,0,1,1);
  local_ec = FLOAT_803dfb5c;
  local_e8 = FLOAT_803dfb78;
  local_e4 = FLOAT_803dfb5c;
  local_e0 = FLOAT_803dfb74;
  local_dc = FLOAT_803dfb5c;
  local_d8 = FLOAT_803dfb5c;
  FUN_8025b9e8(3,&local_ec,-5);
  FUN_8025b94c(2,0,0,7,2,6,6,0,0,0);
  FUN_8025b94c(3,1,0,7,3,0,0,1,0,0);
  FUN_80258674(3,0,0,0x21,0,0x7d);
  FUN_8025c828(2,0xff,0xff,4);
  FUN_8025c1a4(2,0xf,0xf,0xf,0xf);
  FUN_8025c224(2,7,7,7,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  FUN_8025c828(3,3,0,4);
  FUN_8025c1a4(3,8,2,3,0xf);
  FUN_8025c224(3,7,7,7,5);
  FUN_8025c65c(3,0,0);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c368(3,0,0,0,1,0);
  FUN_8025cce8(1,4,5,5);
  FUN_80259288(0);
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

