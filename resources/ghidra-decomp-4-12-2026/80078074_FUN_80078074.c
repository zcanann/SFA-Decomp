// Function: FUN_80078074
// Entry: 80078074
// Size: 2120 bytes

/* WARNING: Removing unreachable block (ram,0x8007889c) */
/* WARNING: Removing unreachable block (ram,0x80078894) */
/* WARNING: Removing unreachable block (ram,0x8007808c) */
/* WARNING: Removing unreachable block (ram,0x80078084) */

void FUN_80078074(undefined4 param_1,undefined4 param_2,float *param_3)

{
  undefined uVar1;
  byte bVar2;
  float *pfVar3;
  int iVar4;
  uint uVar5;
  int unaff_r31;
  double extraout_f1;
  double dVar6;
  double in_f30;
  double in_f31;
  double dVar7;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar8;
  uint3 local_178;
  undefined4 local_174;
  undefined4 local_170;
  undefined4 local_16c;
  int local_168;
  undefined4 local_164;
  undefined4 local_160;
  undefined4 local_15c;
  undefined2 local_158;
  undefined local_156;
  float local_154;
  float local_150;
  float local_14c;
  int local_148 [4];
  undefined4 local_138;
  undefined4 local_134;
  undefined4 local_130;
  uint local_12c [4];
  undefined4 local_11c;
  undefined4 local_118;
  undefined4 local_114;
  int local_110 [4];
  undefined4 local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  uint local_f4 [4];
  undefined4 local_e4;
  undefined4 local_e0;
  undefined4 local_dc;
  int local_d8 [4];
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  uint local_bc [4];
  undefined4 local_ac;
  undefined4 local_a8;
  undefined4 local_a4;
  float afStack_a0 [12];
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar8 = FUN_8028683c();
  pfVar3 = (float *)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  local_bc[0] = DAT_802c2640;
  local_bc[1] = DAT_802c2644;
  local_bc[2] = DAT_802c2648;
  local_bc[3] = DAT_802c264c;
  local_ac = DAT_802c2650;
  local_a8 = DAT_802c2654;
  local_a4 = DAT_802c2658;
  local_d8[0] = DAT_802c265c;
  local_d8[1] = DAT_802c2660;
  local_d8[2] = DAT_802c2664;
  local_d8[3] = DAT_802c2668;
  local_c8 = DAT_802c266c;
  local_c4 = DAT_802c2670;
  local_c0 = DAT_802c2674;
  local_f4[0] = DAT_802c2678;
  local_f4[1] = DAT_802c267c;
  local_f4[2] = DAT_802c2680;
  local_f4[3] = DAT_802c2684;
  local_e4 = DAT_802c2688;
  local_e0 = DAT_802c268c;
  local_dc = DAT_802c2690;
  local_110[0] = DAT_802c2694;
  local_110[1] = DAT_802c2698;
  local_110[2] = DAT_802c269c;
  local_110[3] = DAT_802c26a0;
  local_100 = DAT_802c26a4;
  local_fc = DAT_802c26a8;
  local_f8 = DAT_802c26ac;
  local_12c[0] = DAT_802c26b0;
  local_12c[1] = DAT_802c26b4;
  local_12c[2] = DAT_802c26b8;
  local_12c[3] = DAT_802c26bc;
  local_11c = DAT_802c26c0;
  local_118 = DAT_802c26c4;
  local_114 = DAT_802c26c8;
  local_148[0] = DAT_802c26cc;
  local_148[1] = DAT_802c26d0;
  local_148[2] = DAT_802c26d4;
  local_148[3] = DAT_802c26d8;
  local_138 = DAT_802c26dc;
  local_134 = DAT_802c26e0;
  local_130 = DAT_802c26e4;
  local_15c = DAT_803dfb2c;
  local_158 = DAT_803dfb30;
  local_156 = DAT_803dfb32;
  local_16c = DAT_803e90d0;
  dVar6 = extraout_f1;
  FUN_80247618(pfVar3,param_3,&local_70);
  FUN_8025d8c4(&local_70,0x1e,1);
  FUN_80258674(0,1,0,0x1e,0,0x7d);
  FUN_8004c460((int)pfVar3[0x18],0);
  if (*(byte *)((int)pfVar3 + 0x65) < 8) {
    FUN_8025c6b4(1,0,0,0,0);
    unaff_r31 = *(byte *)((int)pfVar3 + 0x65) - 1;
  }
  else if (*(byte *)((int)pfVar3 + 0x65) < 0x10) {
    FUN_8025c6b4(1,3,3,3,3);
    unaff_r31 = *(byte *)((int)pfVar3 + 0x65) - 9;
  }
  if (unaff_r31 < 0) {
    unaff_r31 = 0;
  }
  local_164 = CONCAT13(0x7f,CONCAT12(0x7f,local_164._2_2_));
  local_164._2_2_ = CONCAT11(0x7f,(undefined)local_164);
  local_170 = local_164;
  FUN_8025c428(1,(byte *)&local_170);
  *(char *)(iVar4 + 3) =
       (char)((int)(uint)*(byte *)(iVar4 + 3) >> 1) + (char)((int)(uint)*(byte *)(iVar4 + 3) >> 2);
  uVar1 = *(undefined *)(iVar4 + 3);
  local_160 = CONCAT13(uVar1,CONCAT12(uVar1,local_160._2_2_));
  local_160._2_2_ = CONCAT11(uVar1,(undefined)local_160);
  local_174 = local_160;
  FUN_8025c510(0,(byte *)&local_174);
  bVar2 = *(byte *)((int)&local_15c + unaff_r31);
  if (bVar2 != 0) {
    FUN_8025be80(0);
    FUN_8025c65c(0,0,1);
    FUN_8025c828(0,0,0,0xff);
    FUN_8025c1a4(0,0xf,8,0xc,local_bc[unaff_r31]);
    FUN_8025c224(0,7,7,7,7);
    FUN_8025c2a8(0,0,0,local_d8[unaff_r31],0,0);
    FUN_8025c368(0,0,0,0,0,0);
  }
  uVar5 = (uint)(bVar2 != 0);
  if (1 < bVar2) {
    FUN_8025be80(uVar5);
    FUN_8025c65c(uVar5,0,0);
    FUN_8025c828(uVar5,0xff,0xff,0xff);
    FUN_8025c1a4(uVar5,0xf,0,0xc,local_f4[unaff_r31]);
    FUN_8025c224(uVar5,7,7,7,7);
    FUN_8025c2a8(uVar5,0,0,local_110[unaff_r31],0,0);
    FUN_8025c368(uVar5,0,0,0,0,0);
    uVar5 = uVar5 + 1;
  }
  if (2 < bVar2) {
    FUN_8025be80(uVar5);
    FUN_8025c65c(uVar5,0,0);
    FUN_8025c828(uVar5,0xff,0xff,0xff);
    FUN_8025c1a4(uVar5,0xf,0,0xc,local_12c[unaff_r31]);
    FUN_8025c224(uVar5,7,7,7,7);
    FUN_8025c2a8(uVar5,0,0,local_148[unaff_r31],0,0);
    FUN_8025c368(uVar5,0,0,0,0,0);
    uVar5 = uVar5 + 1;
  }
  FUN_8025be80(uVar5);
  FUN_8025c65c(uVar5,0,0);
  FUN_8025c584(uVar5,0xc);
  FUN_8025c828(uVar5,0xff,0xff,0xff);
  if (bVar2 == 0) {
    FUN_8025c1a4(uVar5,8,2,0xe,0xf);
  }
  else {
    FUN_8025c1a4(uVar5,0,2,0xe,0xf);
  }
  FUN_8025c224(uVar5,7,7,7,7);
  FUN_8025c2a8(uVar5,8,0,0,1,0);
  FUN_8025c368(uVar5,0,0,0,1,0);
  local_154 = param_3[3];
  local_150 = param_3[7];
  local_14c = param_3[0xb];
  FUN_80247bf8(pfVar3 + 0xc,&local_154,&local_154);
  dVar7 = -(double)local_14c;
  FUN_8006c734(&local_168);
  FUN_8004c460(local_168,1);
  local_70 = FLOAT_803dfb5c;
  local_6c = FLOAT_803dfb5c;
  dVar6 = (double)(float)(dVar7 - (double)(float)(dVar7 - dVar6));
  local_68 = (float)((double)FLOAT_803dfb64 / dVar6);
  local_64 = (float)(dVar7 / dVar6);
  local_60 = FLOAT_803dfb5c;
  local_5c = FLOAT_803dfb5c;
  local_58 = FLOAT_803dfb5c;
  local_54 = FLOAT_803dfb5c;
  FUN_80247618(pfVar3 + 0xc,param_3,afStack_a0);
  FUN_80247618(&local_70,afStack_a0,afStack_a0);
  FUN_8025d8c4(afStack_a0,0x21,1);
  FUN_80258674(1,1,0,0x21,0,0x7d);
  FUN_8025be80(uVar5 + 1);
  FUN_8025c65c(uVar5 + 1,0,0);
  FUN_8025c828(uVar5 + 1,1,1,0xff);
  FUN_8025c1a4(uVar5 + 1,0,0xf,8,0xf);
  FUN_8025c224(uVar5 + 1,7,7,7,7);
  FUN_8025c2a8(uVar5 + 1,0,0,0,1,0);
  FUN_8025c368(uVar5 + 1,0,0,0,1,0);
  FUN_8025be54(0);
  FUN_8025a608(4,0,0,0,0,0,2);
  FUN_8025a608(5,0,0,0,0,0,2);
  FUN_8025a5bc(0);
  FUN_80258944(2);
  FUN_8025ca04((uint)(byte)(bVar2 + 2));
  _local_178 = local_16c;
  FUN_8025ca38((double)FLOAT_803ddca4,(double)FLOAT_803ddca0,(double)FLOAT_803ddcb8,
               (double)FLOAT_803ddcb4,4,&local_178);
  FUN_8025cce8(1,0,3,5);
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
  FUN_80286888();
  return;
}

