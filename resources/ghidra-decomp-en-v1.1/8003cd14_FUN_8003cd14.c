// Function: FUN_8003cd14
// Entry: 8003cd14
// Size: 2780 bytes

/* WARNING: Removing unreachable block (ram,0x8003d7d0) */
/* WARNING: Removing unreachable block (ram,0x8003cd24) */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_8003cd14(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  bool bVar3;
  undefined uVar4;
  undefined2 uVar5;
  int iVar6;
  uint *puVar7;
  uint uVar8;
  int *piVar9;
  float *pfVar10;
  int iVar11;
  uint uVar12;
  int *piVar13;
  double in_f31;
  double dVar14;
  double in_ps31_1;
  undefined8 uVar15;
  int local_170;
  undefined4 uStack_16c;
  uint3 local_168;
  undefined4 local_164;
  int local_160;
  undefined4 uStack_15c;
  float local_158;
  float local_154;
  int local_150;
  uint local_14c;
  int local_148;
  uint local_144;
  uint local_140;
  uint local_13c;
  uint local_138;
  float local_134;
  float local_130;
  undefined4 local_12c;
  undefined4 local_128;
  undefined4 local_124;
  float local_120;
  float local_11c;
  undefined4 local_118;
  undefined4 local_114;
  undefined4 local_110;
  float local_10c;
  undefined4 local_108;
  float local_104 [5];
  float local_f0;
  float afStack_d4 [12];
  float afStack_a4 [12];
  float afStack_74 [13];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar15 = FUN_80286840();
  iVar11 = (int)((ulonglong)uVar15 >> 0x20);
  piVar13 = (int *)uVar15;
  local_13c = DAT_803df674;
  local_138 = DAT_803df678;
  local_11c = DAT_802c2290;
  local_118 = DAT_802c2294;
  local_114 = DAT_802c2298;
  local_110 = DAT_802c229c;
  local_10c = DAT_802c22a0;
  local_108 = DAT_802c22a4;
  local_134 = DAT_802c22a8;
  local_130 = DAT_802c22ac;
  local_12c = DAT_802c22b0;
  local_128 = DAT_802c22b4;
  local_124 = DAT_802c22b8;
  local_120 = DAT_802c22bc;
  iVar6 = FUN_800284e8(*piVar13,param_3);
  if ((*(uint *)(iVar6 + 0x3c) & 0x200) == 0) {
    DAT_803dd8be = 0;
  }
  else {
    DAT_803dd8be = 1;
    FUN_8006c65c(&local_148,&local_14c);
    fVar2 = FLOAT_803df684;
    if (DAT_803dd8b5 == '\0') {
      uStack_3c = DAT_803dd8c4 ^ 0x80000000;
      local_40 = 0x43300000;
      uStack_34 = local_14c ^ 0x80000000;
      local_38 = 0x43300000;
      fVar2 = ((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803df6c0) /
              (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803df6c0)) * FLOAT_803df6a8;
    }
    dVar14 = (double)fVar2;
    puVar7 = (uint *)FUN_8004c3cc(iVar6,0);
    uVar8 = FUN_8005383c(*puVar7);
    FUN_8004c460(uVar8,0);
    FUN_80258674(2,1,4,0x3c,0,0x7d);
    if (DAT_803dd8b6 == '\0') {
      FUN_8025c1a4(0,0xf,0xf,0xf,8);
    }
    else {
      if (DAT_803dd8b6 == '\x01') {
        uVar4 = (undefined)(DAT_803dd8c4 << 4);
        _DAT_803dc0f4 = CONCAT13(uVar4,CONCAT12(uVar4,CONCAT11(uVar4,(undefined)DAT_803dc0f4_1)));
        FUN_8025c1a4(0,8,0xc,0xe,0xf);
      }
      else {
        if ((int)DAT_803dd8c4 < 8) {
          DAT_803dc0f4_1._1_2_ = CONCAT11((char)(DAT_803dd8c4 << 5),(undefined)DAT_803dc0f4_1);
          uVar5 = DAT_803dc0f4_1._1_2_;
        }
        else {
          DAT_803dc0f4_1._1_2_ = CONCAT11(0xff,(undefined)DAT_803dc0f4_1);
          uVar5 = DAT_803dc0f4_1._1_2_;
        }
        DAT_803dc0f4_1._1_1_ = (undefined)((ushort)uVar5 >> 8);
        uVar4 = DAT_803dc0f4_1._1_1_;
        DAT_803dc0f4_1 = CONCAT12(DAT_803dc0f4_1._1_1_,uVar5);
        _DAT_803dc0f4 = CONCAT13(uVar4,DAT_803dc0f4_1);
        FUN_8025c1a4(0,8,0xf,0xe,0xf);
      }
      local_164 = _DAT_803dc0f4;
      FUN_8025c510(1,(byte *)&local_164);
      FUN_8025c5f0(0,0x1d);
      FUN_8025c584(0,0xd);
    }
    FUN_8025be80(0);
    FUN_8025c828(0,2,0,0xff);
    FUN_8025c224(0,7,7,7,7);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,0,0);
    FUN_8025c368(0,0,0,0,1,0);
    bVar1 = *(byte *)(iVar11 + 0xf1);
    local_13c = (uint)CONCAT12(bVar1,(ushort)bVar1);
    local_138 = (uint)CONCAT12(bVar1,*(byte *)(iVar11 + 0x37) - 0xff);
    local_144 = local_13c;
    local_140 = local_138;
    FUN_8025c49c(3,(short *)&local_144);
    FUN_80247a7c((double)FLOAT_803df6ac,(double)FLOAT_803df6ac,(double)FLOAT_803df684,afStack_a4);
    FUN_80247a48((double)FLOAT_803df6a8,(double)FLOAT_803df6a8,(double)FLOAT_803df69c,afStack_d4);
    FUN_80247618(afStack_d4,afStack_a4,afStack_a4);
    FUN_8025d8c4(afStack_a4,0x43,0);
    FUN_80258674(0,1,1,0x1e,0,0x43);
    piVar9 = (int *)FUN_8002867c((int)piVar13,param_3);
    FUN_8004c460(*piVar9,1);
    FUN_8025be80(1);
    FUN_8025c828(1,0,1,4);
    FUN_8025c65c(1,0,0);
    FUN_8025c1a4(1,0xf,8,6,10);
    FUN_8025c224(1,7,7,7,3);
    FUN_8025c2a8(1,0,0,0,1,2);
    FUN_8025c368(1,0,0,0,0,0);
    if ((DAT_803dd8dc == 0) || (FUN_8001d8bc(DAT_803dd8e4,&local_170,&uStack_16c), local_170 != 0))
    {
      bVar3 = false;
    }
    else {
      bVar3 = true;
    }
    if (bVar3) {
      FUN_8025be80(2);
      pfVar10 = (float *)FUN_8001d8dc(DAT_803dd8e4);
      FUN_8025d8c4(pfVar10,0x49,0);
      FUN_80258674(1,0,0,0,0,0x49);
      if ((DAT_803dd8e0 == '\0') || (DAT_803dd8e0 == '\x02')) {
        FUN_8025c828(2,1,5,4);
      }
      else {
        FUN_8025c828(2,1,5,5);
      }
      iVar11 = FUN_8001da48(DAT_803dd8e4);
      FUN_8004c460(iVar11,5);
      FUN_8001d8bc(DAT_803dd8e4,&uStack_15c,&local_160);
      if (local_160 == 2) {
        FUN_8025c1a4(2,0xf,4,8,0xf);
      }
      else if (local_160 == 3) {
        FUN_8025c1a4(2,4,0xf,8,0xf);
      }
      else if (local_160 == 1) {
        FUN_8025c1a4(2,0xf,0xf,8,4);
      }
      else if ((DAT_803dd8e0 == '\0') || (DAT_803dd8e0 == '\x01')) {
        FUN_8025c1a4(2,0xf,10,8,4);
      }
      else {
        FUN_8025c1a4(2,0xf,0xb,8,4);
      }
      FUN_8025c65c(2,0,0);
      if (local_160 == 1) {
        FUN_8025c2a8(2,1,0,0,1,2);
      }
      else {
        FUN_8025c2a8(2,0,0,0,1,2);
      }
      FUN_8025c224(2,7,7,7,0);
      FUN_8025c368(2,0,0,0,1,0);
      uVar8 = 3;
      iVar11 = 5;
    }
    else {
      uVar8 = 2;
      iVar11 = 1;
    }
    FUN_8006c760(&local_150);
    FUN_8004c460(local_150,4);
    FUN_8006cc38(&local_154,&local_158);
    FUN_80247a48((double)(FLOAT_803df6a8 * local_154),(double)(FLOAT_803df6a8 * local_158),
                 (double)FLOAT_803df684,local_104);
    local_104[0] = FLOAT_803df69c;
    local_f0 = FLOAT_803df69c;
    FUN_8025d8c4(local_104,0x46,0);
    FUN_80258674(iVar11,1,4,0x3c,0,0x46);
    FUN_8025bd1c(0,iVar11,4);
    FUN_8025bb48(0,0,0);
    local_11c = (float)dVar14;
    local_10c = (float)dVar14;
    FUN_8025b9e8(1,&local_11c,(char)DAT_803dc0ec);
    FUN_8025b94c(uVar8,0,0,7,1,6,6,0,0,0);
    FUN_8025c828(uVar8,0xff,0xff,0xff);
    FUN_8025c65c(uVar8,0,0);
    FUN_8025c1a4(uVar8,0xf,0,4,0xf);
    FUN_8025c224(uVar8,7,7,7,0);
    FUN_8025c2a8(uVar8,0,0,0,1,0);
    FUN_8025c368(uVar8,0,0,0,0,0);
    if (*(uint *)(iVar6 + 0x38) == 0) {
      FUN_8025bd1c(1,3,2);
      FUN_8025bb48(1,0,0);
      local_130 = FLOAT_803df684;
      local_120 = FLOAT_803df684;
      FUN_8025b9e8(2,&local_134,-0xf);
      FUN_8025b94c(uVar8 + 1,1,0,7,2,0,0,1,0,0);
    }
    else {
      uVar12 = FUN_8005383c(*(uint *)(iVar6 + 0x38));
      FUN_8004c460(uVar12,2);
      FUN_80258674(3,1,4,0x3c,0,0x7d);
      FUN_8025bd1c(1,3,2);
      FUN_8025bb48(1,0,0);
      local_130 = (float)dVar14;
      local_120 = (float)dVar14;
      FUN_8025b9e8(2,&local_134,(char)DAT_803dc0f0);
      FUN_8025b94c(uVar8 + 1,1,0,7,2,0,0,1,0,1);
    }
    FUN_8004c460(*(int *)(local_148 + DAT_803dd8c4 * 4),3);
    FUN_80247a7c((double)FLOAT_803df6b0,(double)FLOAT_803df6b0,(double)FLOAT_803df69c,afStack_74);
    FUN_8025d8c4(afStack_74,0x40,0);
    FUN_80258674(4,1,4,0x3c,1,0x40);
    FUN_8025c584(uVar8 + 1,4);
    if (*(int *)(iVar6 + 0x38) == 0) {
      FUN_8025c828(uVar8 + 1,4,3,0xff);
      FUN_8025c224(uVar8 + 1,4,7,7,0);
    }
    else {
      FUN_8025c828(uVar8 + 1,4,3,8);
      FUN_8025c224(uVar8 + 1,7,4,5,0);
    }
    FUN_8025c1a4(uVar8 + 1,8,0xe,0,0);
    FUN_8025c65c(uVar8 + 1,0,0);
    FUN_8025c2a8(uVar8 + 1,1,1,0,1,0);
    FUN_8025c368(uVar8 + 1,0,0,0,1,0);
    if (bVar3) {
      FUN_8025ca04(5);
      FUN_80258944(6);
    }
    else {
      FUN_8025ca04(4);
      FUN_80258944(5);
    }
    FUN_8025be54(2);
    FUN_80259288(2);
    if ((*(ushort *)(*piVar13 + 2) & 0x100) == 0) {
      FUN_80070540();
    }
    else {
      _local_168 = DAT_803dc0c8;
      dVar14 = (double)FLOAT_803df684;
      FUN_8025ca38(dVar14,dVar14,dVar14,dVar14,0,&local_168);
    }
    FUN_8007048c(1,3,0);
    FUN_80070434(1);
    FUN_8025cce8(1,4,5,5);
  }
  FUN_8028688c();
  return;
}

