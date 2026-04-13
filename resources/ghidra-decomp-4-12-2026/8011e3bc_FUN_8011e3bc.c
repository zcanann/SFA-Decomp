// Function: FUN_8011e3bc
// Entry: 8011e3bc
// Size: 1464 bytes

/* WARNING: Removing unreachable block (ram,0x8011e954) */
/* WARNING: Removing unreachable block (ram,0x8011e3cc) */

undefined4 FUN_8011e3bc(int param_1,int *param_2,int param_3)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  double dVar4;
  undefined4 local_100;
  uint local_fc;
  uint local_f8;
  int local_f4;
  float local_f0;
  undefined4 local_ec;
  undefined4 local_e8;
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  float afStack_d8 [12];
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float afStack_78 [2];
  float local_70;
  float local_60;
  float afStack_48 [3];
  float local_3c;
  float local_2c;
  float local_1c;
  
  local_f8 = DAT_803e2ab0;
  local_f0 = DAT_802c292c;
  local_ec = DAT_802c2930;
  local_e8 = DAT_802c2934;
  local_e4 = DAT_802c2938;
  local_e0 = DAT_802c293c;
  local_dc = DAT_802c2940;
  iVar1 = FUN_800284e8(*param_2,param_3);
  puVar2 = (uint *)FUN_8004c3cc(iVar1,0);
  uVar3 = FUN_8005383c(*puVar2);
  FUN_802475e4((float *)&DAT_803a95b0,afStack_48);
  local_3c = FLOAT_803e2abc;
  local_2c = FLOAT_803e2abc;
  local_1c = FLOAT_803e2abc;
  FUN_80247a7c((double)(FLOAT_803e2ae4 / FLOAT_803de48c),(double)(FLOAT_803e2ae4 / FLOAT_803de48c),
               (double)(FLOAT_803e2ae8 / FLOAT_803de48c),afStack_78);
  local_70 = FLOAT_803e2aec / FLOAT_803de48c;
  local_60 = local_70;
  FUN_80247618(afStack_78,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x1e,1);
  FUN_80258944(3);
  FUN_8025ca04(3);
  FUN_8025be54(2);
  FUN_8025a5bc(1);
  FUN_8025bd1c(0,0,2);
  FUN_8025bb48(0,0,0);
  FUN_8025b9e8(1,&local_f0,'\0');
  FUN_8025b94c(0,0,0,7,1,0,0,0,0,0);
  FUN_8004c460(uVar3,0);
  FUN_80258674(0,1,1,0x1e,0,0x7d);
  FUN_8025c828(0,0,0,4);
  FUN_8025c1a4(0,0xf,0xf,0xf,10);
  FUN_8025c224(0,7,7,7,5);
  FUN_8025c65c(0,0,0);
  FUN_8025c2a8(0,0,0,0,1,0);
  FUN_8025c368(0,0,0,0,1,0);
  FUN_8025a608(4,0,0,0,0,0,2);
  local_fc = local_f8;
  FUN_8025a454(4,&local_fc);
  FUN_8025bd1c(1,0,2);
  FUN_8025bb48(1,0,0);
  FUN_8025b94c(1,1,0,7,1,0,0,1,0,0);
  FUN_80247618((float *)&DAT_80397480,(float *)&DAT_803a95b0,afStack_48);
  dVar4 = (double)(FLOAT_803e2af0 * FLOAT_803de4d0 * FLOAT_803de4d0);
  FUN_80247a7c(dVar4,dVar4,(double)FLOAT_803e2ae8,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  dVar4 = (double)(FLOAT_803e2af0 * (float)((double)FLOAT_803e2ae8 - dVar4));
  FUN_80247a48(dVar4,dVar4,(double)FLOAT_803e2abc,afStack_d8);
  FUN_80247618(afStack_d8,afStack_48,afStack_48);
  FUN_8025d8c4(afStack_48,0x21,0);
  FUN_80258674(1,0,0,0x21,0,0x7d);
  FUN_8025c828(1,1,0,0xff);
  FUN_8025c1a4(1,0xf,0xf,0xf,8);
  FUN_8025c224(1,7,7,7,0);
  FUN_8025c65c(1,0,0);
  FUN_8025c2a8(1,0,0,0,1,0);
  FUN_8025c368(1,0,0,0,1,0);
  local_a8 = FLOAT_803dc77c;
  local_a4 = FLOAT_803e2abc;
  local_a0 = FLOAT_803e2abc;
  local_9c = FLOAT_803e2af0;
  local_98 = FLOAT_803e2abc;
  local_94 = FLOAT_803dc77c;
  local_90 = FLOAT_803e2abc;
  local_8c = FLOAT_803e2af0;
  local_88 = FLOAT_803e2abc;
  local_84 = FLOAT_803e2abc;
  local_80 = FLOAT_803e2abc;
  local_7c = FLOAT_803e2ae8;
  FUN_8025d8c4(&local_a8,0x24,1);
  FUN_80258674(2,1,1,0x24,0,0x7d);
  FUN_8006c748(&local_f4);
  FUN_8004c460(local_f4,1);
  FUN_8025c5f0(2,0x1c);
  local_100 = DAT_803dc778;
  FUN_8025c510(0,(byte *)&local_100);
  FUN_8025be80(2);
  FUN_8025c828(2,2,1,0xff);
  FUN_8025c1a4(2,0xf,0xf,0xf,0);
  FUN_8025c224(2,7,4,6,0);
  FUN_8025c65c(2,0,0);
  FUN_8025c2a8(2,0,0,0,1,0);
  FUN_8025c368(2,1,0,0,1,0);
  if (*(short *)(param_1 + 0x46) == 0x755) {
    FUN_80259288(1);
  }
  else {
    FUN_80259288(2);
  }
  FUN_8025cce8(1,4,5,5);
  FUN_8007048c(0,7,0);
  FUN_80070434(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  return 1;
}

