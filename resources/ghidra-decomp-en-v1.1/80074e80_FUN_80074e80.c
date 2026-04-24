// Function: FUN_80074e80
// Entry: 80074e80
// Size: 1716 bytes

/* WARNING: Removing unreachable block (ram,0x80075510) */
/* WARNING: Removing unreachable block (ram,0x80074e90) */

undefined4 FUN_80074e80(int param_1,int *param_2)

{
  float *pfVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  undefined4 local_12c;
  undefined4 local_128;
  float local_124;
  float local_120;
  int local_11c;
  int local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float afStack_e4 [12];
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float afStack_84 [3];
  float local_78;
  float local_68;
  float afStack_54 [3];
  float local_48;
  
  pfVar1 = (float *)FUN_8000f56c();
  if (param_2 == (int *)0x0) {
    dVar3 = (double)FLOAT_803dfb64;
  }
  else {
    pfVar2 = (float *)FUN_80028630(param_2,0);
    FUN_80247618(pfVar1,pfVar2,&local_b4);
    dVar4 = (double)(local_88 * local_88 + local_a8 * local_a8 + local_98 * local_98);
    if ((double)FLOAT_803dfb5c < dVar4) {
      dVar3 = 1.0 / SQRT(dVar4);
      dVar3 = DOUBLE_803dfb90 * dVar3 * -(dVar4 * dVar3 * dVar3 - DOUBLE_803dfb98);
      dVar3 = DOUBLE_803dfb90 * dVar3 * -(dVar4 * dVar3 * dVar3 - DOUBLE_803dfb98);
      dVar4 = (double)(float)(dVar4 * DOUBLE_803dfb90 * dVar3 *
                                      -(dVar4 * dVar3 * dVar3 - DOUBLE_803dfb98));
    }
    dVar3 = (double)(float)((double)FLOAT_803dfbbc / dVar4);
    if ((double)FLOAT_803dfb64 < (double)(float)((double)FLOAT_803dfbbc / dVar4)) {
      dVar3 = (double)FLOAT_803dfb64;
    }
  }
  FUN_8006c86c(0);
  FUN_8025d8c4((float *)&DAT_80397480,0x52,0);
  FUN_80258674(0,0,0,0,0,0x52);
  FUN_8006cc38(&local_120,&local_124);
  local_120 = local_120 * FLOAT_803dfbac;
  local_124 = local_124 * FLOAT_803dfbac;
  FUN_8006c760(&local_118);
  FUN_8004c460(local_118,1);
  dVar4 = (double)FLOAT_803dfbac;
  FUN_80247a7c(dVar4,dVar4,dVar4,afStack_54);
  local_48 = local_120;
  FUN_8025d8c4(afStack_54,0x21,1);
  FUN_80258674(1,1,4,0x21,0,0x7d);
  local_fc = (float)((double)FLOAT_803dfb78 * dVar3);
  local_f8 = FLOAT_803dfb5c;
  local_f4 = FLOAT_803dfb5c;
  local_f0 = FLOAT_803dfb5c;
  local_e8 = FLOAT_803dfb5c;
  local_ec = local_fc;
  FUN_8025bd1c(0,1,1);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_fc,-4);
  FUN_8025b94c(0,0,0,7,1,6,6,0,0,0);
  dVar4 = (double)FLOAT_803dfbc0;
  FUN_80247a7c(dVar4,dVar4,dVar4,afStack_84);
  FUN_8024782c((double)FLOAT_803dfb70,afStack_e4,0x7a);
  FUN_80247618(afStack_e4,afStack_84,afStack_84);
  local_78 = local_124;
  local_68 = local_124;
  FUN_8025d8c4(afStack_84,0x24,1);
  FUN_80258674(2,1,4,0x24,0,0x7d);
  local_114 = (float)((double)FLOAT_803dfbc4 * dVar3);
  local_10c = FLOAT_803dfb5c;
  local_108 = (float)((double)FLOAT_803dfbc8 * dVar3);
  local_100 = FLOAT_803dfb5c;
  local_110 = local_114;
  local_104 = local_114;
  FUN_8025bd1c(1,2,1);
  FUN_8025bb48(1,0,0);
  FUN_8025b9e8(2,&local_114,-4);
  FUN_8025b94c(1,1,0,7,2,0,0,1,0,0);
  local_b4 = FLOAT_803dc30c;
  local_b0 = FLOAT_803dfb5c;
  local_ac = FLOAT_803dfb5c;
  local_a8 = FLOAT_803dfb78;
  local_a4 = FLOAT_803dfb5c;
  local_a0 = FLOAT_803dc30c;
  local_9c = FLOAT_803dfb5c;
  local_98 = FLOAT_803dfb78;
  local_94 = FLOAT_803dfb5c;
  local_90 = FLOAT_803dfb5c;
  local_8c = FLOAT_803dfb5c;
  local_88 = FLOAT_803dfb64;
  FUN_8025d8c4(&local_b4,0x55,0);
  FUN_80258674(3,0,1,0x1e,0,0x55);
  FUN_8006c748(&local_11c);
  FUN_8004c460(local_11c,2);
  FUN_8025be54(2);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(4);
  FUN_8025ca04(3);
  FUN_8025c828(0,0,0,0xff);
  FUN_8025c1a4(0,0xf,0xf,0xf,0xf);
  FUN_8025c224(0,7,7,7,7);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025c828(1,0,0,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,8);
  FUN_8025c224(1,7,7,7,7);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  local_128 = CONCAT31(local_128._0_3_,*(undefined *)(param_1 + 0x37));
  local_12c = local_128;
  FUN_8025c510(0,(byte *)&local_12c);
  FUN_8025c5f0(2,0x1c);
  FUN_8025be80(2);
  FUN_8025c828(2,3,2,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,6,7);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,0,0,0,1,0);
  if ((((DAT_803ddc98 != '\x01') || (DAT_803ddc94 != 3)) || (DAT_803ddc92 != '\0')) ||
     (DAT_803ddc9a == '\0')) {
    FUN_8025ce6c(1,3,0);
    DAT_803ddc98 = '\x01';
    DAT_803ddc94 = 3;
    DAT_803ddc92 = '\0';
    DAT_803ddc9a = '\x01';
  }
  FUN_8025cce8(1,4,5,5);
  if ((DAT_803ddc91 != '\x01') || (DAT_803ddc99 == '\0')) {
    FUN_8025cee4(1);
    DAT_803ddc91 = '\x01';
    DAT_803ddc99 = '\x01';
  }
  FUN_8025c754(7,0,0,7,0);
  FUN_80259288(2);
  return 1;
}

