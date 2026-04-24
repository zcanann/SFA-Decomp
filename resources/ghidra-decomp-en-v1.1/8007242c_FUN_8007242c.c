// Function: FUN_8007242c
// Entry: 8007242c
// Size: 2892 bytes

/* WARNING: Removing unreachable block (ram,0x80072f60) */
/* WARNING: Removing unreachable block (ram,0x80072f58) */
/* WARNING: Removing unreachable block (ram,0x80072444) */
/* WARNING: Removing unreachable block (ram,0x8007243c) */

void FUN_8007242c(double param_1,double param_2,float *param_3,byte *param_4)

{
  float fVar1;
  char cVar2;
  char cVar3;
  char cVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double in_f30;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  int local_10c;
  undefined4 local_108;
  undefined4 local_104;
  undefined4 local_100;
  undefined4 local_fc;
  float fStack_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  int local_e0;
  int local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float afStack_c0 [12];
  float afStack_90 [12];
  float afStack_60 [12];
  longlong local_30;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_fc._0_1_ = (char)((uint)DAT_803dfb38 >> 0x18);
  cVar2 = (char)((int)(uint)*param_4 >> 2);
  local_fc._1_1_ = (char)((uint)DAT_803dfb38 >> 0x10);
  cVar3 = (char)((int)(uint)param_4[1] >> 2);
  local_fc._2_1_ = (char)((uint)DAT_803dfb38 >> 8);
  cVar4 = (char)((int)(uint)param_4[2] >> 2);
  local_fc._2_1_ = local_fc._2_1_ + cVar4;
  local_fc._3_1_ = (undefined)DAT_803dfb38;
  local_fc = CONCAT22(CONCAT11(local_fc._0_1_ + cVar2,local_fc._1_1_ + cVar3),
                      CONCAT11(local_fc._2_1_,(undefined)local_fc));
  local_100._0_1_ = (char)((uint)DAT_803dfb3c >> 0x18);
  local_100._1_1_ = (char)((uint)DAT_803dfb3c >> 0x10);
  local_100._2_1_ = (char)((uint)DAT_803dfb3c >> 8);
  local_100._2_1_ = local_100._2_1_ + cVar4;
  local_100._3_1_ = (undefined)DAT_803dfb3c;
  local_100 = CONCAT22(CONCAT11(local_100._0_1_ + cVar2,local_100._1_1_ + cVar3),
                       CONCAT11(local_100._2_1_,(undefined)local_100));
  local_104._0_1_ = (char)((uint)DAT_803dfb40 >> 0x18);
  local_104._1_1_ = (char)((uint)DAT_803dfb40 >> 0x10);
  local_104._2_1_ = (char)((uint)DAT_803dfb40 >> 8);
  local_104._2_1_ = local_104._2_1_ + cVar4;
  local_104._3_1_ = (undefined)DAT_803dfb40;
  local_104 = CONCAT22(CONCAT11(local_104._0_1_ + cVar2,local_104._1_1_ + cVar3),
                       CONCAT11(local_104._2_1_,(undefined)local_104));
  local_108._0_1_ = (char)((uint)DAT_803dfb44 >> 0x18);
  local_108._1_1_ = (char)((uint)DAT_803dfb44 >> 0x10);
  local_108._2_1_ = (char)((uint)DAT_803dfb44 >> 8);
  local_108._2_1_ = local_108._2_1_ + (char)((int)(uint)param_4[2] >> 3);
  local_108._3_1_ = (undefined)DAT_803dfb44;
  local_108 = CONCAT22(CONCAT11(local_108._0_1_ + (char)((int)(uint)*param_4 >> 3),
                                local_108._1_1_ + (char)((int)(uint)param_4[1] >> 3)),
                       CONCAT11(local_108._2_1_,(undefined)local_108));
  FUN_8000eba8((double)(*param_3 - FLOAT_803dda58),(double)param_3[1],
               (double)(param_3[2] - FLOAT_803dda5c),param_1,&local_e4,&local_e8,&local_ec,&local_f0
               ,&local_f4,&fStack_f8);
  local_ec = local_ec + FLOAT_803dfb64;
  iVar5 = FUN_80286718((double)(FLOAT_803dfb88 * local_ec));
  local_fc = CONCAT31(local_fc._0_3_,(char)((uint)iVar5 >> 0x10));
  FUN_8006c86c(0);
  FUN_8006c754(&local_dc);
  FUN_8004c460(local_dc,1);
  FUN_8006c6bc(&local_e0);
  FUN_8004c460(local_e0,2);
  FUN_8025c6b4(1,0,0,0,3);
  FUN_8025c6b4(2,1,1,1,3);
  FUN_8025c6b4(3,2,2,2,3);
  FUN_80258674(0,1,4,0x3c,0,0x7d);
  FUN_80258674(1,1,4,0x3c,0,0x7d);
  FUN_80247a48((double)(FLOAT_803dfb78 * -local_e4 - FLOAT_803dfb78),
               (double)(FLOAT_803dfb78 * local_e8 - FLOAT_803dfb78),(double)FLOAT_803dfb5c,
               afStack_90);
  FUN_80247a7c((double)(FLOAT_803dc324 / local_f0),(double)(FLOAT_803dc324 / local_f4),
               (double)FLOAT_803dfb5c,afStack_c0);
  FUN_80247618(afStack_c0,afStack_90,afStack_60);
  FUN_80247a48((double)FLOAT_803dfb78,(double)FLOAT_803dfb78,(double)FLOAT_803dfb5c,afStack_90);
  FUN_80247618(afStack_90,afStack_60,afStack_60);
  FUN_8025d8c4(afStack_60,0x1e,1);
  FUN_80258674(2,1,4,0x1e,0,0x7d);
  dVar7 = (double)(float)((double)FLOAT_803dc328 / param_1);
  if ((double)FLOAT_803dfb5c < dVar7) {
    dVar6 = 1.0 / SQRT(dVar7);
    dVar6 = DOUBLE_803dfb90 * dVar6 * -(dVar7 * dVar6 * dVar6 - DOUBLE_803dfb98);
    dVar6 = DOUBLE_803dfb90 * dVar6 * -(dVar7 * dVar6 * dVar6 - DOUBLE_803dfb98);
    dVar7 = (double)(float)(dVar7 * DOUBLE_803dfb90 * dVar6 *
                                    -(dVar7 * dVar6 * dVar6 - DOUBLE_803dfb98));
  }
  if (dVar7 <= (double)FLOAT_803dfb64) {
    local_100 = CONCAT31(local_100._0_3_,(char)(int)((double)FLOAT_803dfba0 * dVar7));
  }
  else {
    local_100 = CONCAT31(local_100._0_3_,0xff);
  }
  fVar1 = (float)(dVar7 * (double)FLOAT_803dfb60);
  if (FLOAT_803dfb64 < (float)(dVar7 * (double)FLOAT_803dfb60)) {
    fVar1 = FLOAT_803dfb64;
  }
  local_30 = (longlong)(int)(FLOAT_803dfba0 * fVar1);
  local_108 = CONCAT31(local_108._0_3_,(char)(int)(FLOAT_803dfba0 * fVar1));
  local_110 = local_fc;
  FUN_8025c510(0,(byte *)&local_110);
  local_114 = local_100;
  FUN_8025c510(1,(byte *)&local_114);
  local_118 = local_104;
  FUN_8025c510(2,(byte *)&local_118);
  local_11c = local_108;
  FUN_8025c428(1,(byte *)&local_11c);
  FUN_8006c6b0(&local_10c);
  FUN_8004c460(local_10c,3);
  local_d8 = (float)((double)FLOAT_803dc32c / param_1);
  if (FLOAT_803dfb78 < (float)((double)FLOAT_803dc32c / param_1)) {
    local_d8 = FLOAT_803dfb78;
  }
  local_d4 = FLOAT_803dfb5c;
  local_d0 = FLOAT_803dfb5c;
  local_cc = FLOAT_803dfb5c;
  local_c4 = FLOAT_803dfb5c;
  local_c8 = local_d8;
  FUN_80247a48((double)(FLOAT_803dfb78 * -local_e4 - FLOAT_803dfb78),
               (double)(FLOAT_803dfb78 * local_e8 - FLOAT_803dfb78),(double)FLOAT_803dfb5c,
               afStack_90);
  FUN_80247a7c((double)FLOAT_803dfba4,(double)FLOAT_803dfba4,(double)FLOAT_803dfb5c,afStack_c0);
  FUN_8024782c(param_2,afStack_60,0x7a);
  FUN_80247618(afStack_c0,afStack_90,afStack_c0);
  FUN_80247618(afStack_60,afStack_c0,afStack_60);
  FUN_80247a48((double)FLOAT_803dfb78,(double)FLOAT_803dfb78,(double)FLOAT_803dfb5c,afStack_90);
  FUN_80247618(afStack_90,afStack_60,afStack_60);
  FUN_8025d8c4(afStack_60,0x21,1);
  FUN_80258674(3,1,4,0x21,0,0x7d);
  FUN_8025bd1c(0,3,3);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_d8,'\x01');
  FUN_8025b94c(2,0,0,7,1,0,0,0,0,0);
  FUN_8025b94c(3,0,0,7,1,0,0,0,0,0);
  FUN_8025b94c(4,0,0,7,1,0,0,0,0,0);
  FUN_80258944(4);
  FUN_8025be54(1);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_8025ca04(6);
  FUN_8025c5f0(0,0x1c);
  FUN_8025be80(0);
  FUN_8025c828(0,1,1,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c224(0,4,7,7,6);
  FUN_8025c65c(0,0,1);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,1,0,2,1,3);
  FUN_8025c5f0(1,0x1c);
  FUN_8025be80(1);
  FUN_8025c828(1,1,1,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,0xf);
  FUN_8025c224(1,6,7,7,4);
  FUN_8025c65c(1,0,1);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,1,0,2,1,0);
  FUN_8025c584(2,0xc);
  FUN_8025c828(2,0,0,0xff);
  FUN_8025c1a4(2,0xf,8,0xe,2);
  FUN_8025c224(2,7,0,1,7);
  FUN_8025c65c(2,0,1);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,2,1,0);
  FUN_8025c584(3,0xd);
  FUN_8025c5f0(3,0x1d);
  FUN_8025c828(3,0,0,0xff);
  FUN_8025c1a4(3,0xf,8,0xe,0);
  FUN_8025c224(3,7,3,6,7);
  FUN_8025c65c(3,0,2);
  FUN_8025c2a8(3,0,0,0,1,0);
  FUN_8025c368(3,0,0,2,1,3);
  FUN_8025c584(4,0xe);
  FUN_8025c828(4,0,0,0xff);
  FUN_8025c1a4(4,0xf,8,0xe,0);
  FUN_8025c224(4,3,7,7,0);
  FUN_8025c65c(4,0,3);
  FUN_8025c2a8(4,0,0,0,1,0);
  FUN_8025c368(4,0,0,2,1,0);
  FUN_8025be80(5);
  FUN_8025c828(5,2,2,0xff);
  FUN_8025c1a4(5,0xf,0xf,0xf,0);
  FUN_8025c224(5,4,7,0,7);
  FUN_8025c65c(5,0,0);
  FUN_8025c2a8(5,0,0,0,1,0);
  FUN_8025c368(5,0,0,0,1,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(0xd,1);
  FUN_80259288(0);
  FUN_8025cce8(1,5,4,5);
  if ((((DAT_803ddc98 != '\0') || (DAT_803ddc94 != 7)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(0,7,0);
    DAT_803ddc98 = '\0';
    DAT_803ddc94 = 7;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  FUN_8025d6ac((undefined4 *)&DAT_803974e0,1);
  FUN_8025d888(0x3c);
  FUN_80259000(0x80,0,4);
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x280;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0x80;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x1e0;
  DAT_cc008000._0_2_ = 0xfff8;
  DAT_cc008000._0_2_ = 0;
  DAT_cc008000._0_2_ = 0x80;
  FUN_8000fb20();
  return;
}

