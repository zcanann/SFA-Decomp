// Function: FUN_800404b8
// Entry: 800404b8
// Size: 3160 bytes

/* WARNING: Removing unreachable block (ram,0x800410f0) */
/* WARNING: Removing unreachable block (ram,0x800410e8) */
/* WARNING: Removing unreachable block (ram,0x800410e0) */
/* WARNING: Removing unreachable block (ram,0x800410d8) */
/* WARNING: Removing unreachable block (ram,0x800404e0) */
/* WARNING: Removing unreachable block (ram,0x800404d8) */
/* WARNING: Removing unreachable block (ram,0x800404d0) */
/* WARNING: Removing unreachable block (ram,0x800404c8) */

void FUN_800404b8(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  bool bVar1;
  uint3 uVar2;
  uint uVar3;
  uint uVar4;
  uint3 uVar5;
  ushort *puVar6;
  ushort *puVar7;
  int *piVar8;
  float *pfVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  ushort *puVar13;
  undefined4 *puVar14;
  float *pfVar15;
  uint uVar16;
  undefined *puVar17;
  int *unaff_r26;
  int unaff_r27;
  double dVar18;
  double in_f28;
  double dVar19;
  double dVar20;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar21;
  byte local_218;
  byte local_217 [3];
  uint3 local_214;
  uint3 local_210;
  undefined4 local_20c;
  undefined4 local_208;
  undefined4 local_204;
  int local_200 [4];
  uint local_1f0;
  float afStack_1ec [12];
  float afStack_1bc [12];
  float afStack_18c [16];
  float afStack_14c [16];
  float afStack_10c [16];
  float afStack_cc [3];
  float local_c0;
  float local_b0;
  float local_a0;
  undefined4 local_88;
  uint uStack_84;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  uVar21 = FUN_80286818();
  puVar7 = (ushort *)((ulonglong)uVar21 >> 0x20);
  DAT_803dd8aa = 0;
  DAT_803dd8ac = 0;
  DAT_803dd8b0 = 0;
  DAT_803dd8b4 = 0;
  DAT_803dc0d4 = 0xffffffff;
  DAT_803dc0d8 = 0xff;
  DAT_803dc0d9 = 0xff;
  DAT_803dc0dc = 0xffffffff;
  DAT_803dc0e0 = 0xff;
  DAT_803dc0e1 = 0xff;
  DAT_803dc0e2 = 0xff;
  DAT_803dc0e4._3_1_ = 0;
  DAT_803dc0e4._2_1_ = 0;
  DAT_803dc0e4._1_1_ = 0;
  DAT_803dc0e4._0_1_ = 0;
  piVar8 = (int *)FUN_8002b660((int)puVar7);
  pfVar9 = (float *)FUN_8000f56c();
  if (DAT_803dd8a4 == (float *)0x0) {
    FUN_8002b554(puVar7,afStack_14c,'\0');
  }
  else {
    FUN_802475e4(DAT_803dd8a4,afStack_14c);
    DAT_803dd8a4 = (float *)0x0;
  }
  DAT_803dd8cc = 0;
  if ((*(uint *)(*(int *)(puVar7 + 0x28) + 0x44) & 0x400) != 0) {
    iVar10 = FUN_8002bac4();
    iVar11 = (**(code **)(*DAT_803dd6d0 + 0xc))();
    if (((iVar10 != 0) && ((*(ushort *)(iVar10 + 0xb0) & 0x1000) == 0)) &&
       (*(int *)(iVar11 + 0xa4) == iVar10)) {
      dVar19 = (double)(FLOAT_803df6b8 +
                       *(float *)(puVar7 + 0x54) * *(float *)(puVar7 + 4) +
                       *(float *)(puVar7 + 0x52));
      dVar18 = (double)FUN_8000f4a0((double)*(float *)(iVar10 + 0x18),
                                    (double)*(float *)(iVar10 + 0x1c),
                                    (double)*(float *)(iVar10 + 0x20));
      if (-dVar18 < dVar19) {
        DAT_803dd8cc = 1;
        FLOAT_803dd8d0 = (float)dVar18;
      }
    }
  }
  if (DAT_803dd8a8 == '\0') {
    FUN_80089ab8((uint)*(byte *)(puVar7 + 0x79),(byte *)&DAT_803dd8d4,
                 (byte *)((int)&DAT_803dd8d4 + 1),(byte *)((int)&DAT_803dd8d4 + 2));
  }
  else {
    DAT_803dd8d4._0_1_ = DAT_803dd8d8;
    DAT_803dd8d4._1_1_ = uRam803dd8d9;
    DAT_803dd8d4._2_1_ = uRam803dd8da;
    DAT_803dd8a8 = '\0';
  }
  uVar16 = param_4 & 4;
  if ((uVar16 == 0) && ((param_4 & 8) == 0)) {
    if ((param_4 & 2) != 0) {
      in_f31 = (double)FLOAT_803df6d0;
    }
  }
  else {
    in_f31 = (double)FLOAT_803df6cc;
  }
  bVar1 = false;
  if ((*(ushort *)(piVar8 + 6) & 8) == 0) {
    *(undefined *)(piVar8 + 0x18) = 0;
    FUN_80028608((int)piVar8);
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_8002861c((int)piVar8);
      pfVar12 = (float *)FUN_80028630(piVar8,0);
      FUN_802475e4(afStack_14c,pfVar12);
    }
    else {
      if (*(int *)(param_3 + 0xa4) == 0) {
        FUN_80028c18(piVar8,param_3,(int)puVar7,afStack_14c);
      }
      else {
        FUN_802475b8(afStack_18c);
        FUN_80028c18(piVar8,param_3,(int)puVar7,afStack_18c);
        if (uVar16 == 0) {
          FUN_8002736c(piVar8,afStack_14c,(float *)&DAT_80343a70);
        }
        else {
          FUN_80027280();
        }
        bVar1 = true;
      }
      if ((*(code **)(puVar7 + 0x84) != (code *)0x0) && ((ushort *)uVar21 == puVar7)) {
        (**(code **)(puVar7 + 0x84))(puVar7,piVar8,afStack_14c);
      }
    }
    if (((uVar16 == 0) && ((param_4 & 8) == 0)) || (DAT_803dd8c4 == 0)) {
      if (*(char *)(param_3 + 0xf9) != '\0') {
        FUN_800274c8();
      }
      if (bVar1) {
        if (*(char *)(piVar8 + 0x18) == '\0') {
          iVar10 = *(int *)(param_3 + 0x28);
        }
        else {
          iVar10 = piVar8[(*(ushort *)(piVar8 + 6) >> 1 & 1) + 7];
        }
        FUN_80029c7c(&DAT_80343a70,param_3 + 0x88,iVar10,(int *)piVar8[0x10],
                     piVar8[(*(ushort *)(piVar8 + 6) >> 1 & 1) + 7]);
        FUN_8002990c(&DAT_80343a70,param_3 + 0xac,*(int *)(param_3 + 0x2c),(uint *)piVar8[0x11],
                     *(byte *)(param_3 + 0x24) & 8);
      }
    }
    if (*(char *)(param_3 + 0xf7) == '\0') {
      iVar10 = *(int *)(puVar7 + 0x2a);
      if (iVar10 != 0) {
        *(char *)(iVar10 + 0xaf) = *(char *)(iVar10 + 0xaf) + -1;
        if (*(char *)(*(int *)(puVar7 + 0x2a) + 0xaf) < '\0') {
          *(undefined *)(*(int *)(puVar7 + 0x2a) + 0xaf) = 0;
        }
      }
    }
    else {
      FUN_80027c04(piVar8,param_3,(int)puVar7,(float *)0x0,(int)(ushort *)uVar21);
    }
    *(ushort *)(piVar8 + 6) = *(ushort *)(piVar8 + 6) | 8;
  }
  uVar3 = param_4 & 2;
  if (((uVar3 != 0) || (uVar16 != 0)) || ((param_4 & 8) != 0)) {
    iVar11 = 0;
    dVar19 = (double)FLOAT_803df69c;
    dVar18 = DOUBLE_803df6c0;
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(param_3 + 0xf3); iVar10 = iVar10 + 1) {
      uStack_84 = DAT_803dd8c0 ^ 0x80000000;
      local_88 = 0x43300000;
      dVar20 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) - dVar18) *
                               (double)(float)(in_f31 / (double)*(float *)(*(int *)(param_3 + 0x40)
                                                                          + iVar11 + 0xc)) + dVar19)
      ;
      pfVar12 = (float *)FUN_80028630(piVar8,iVar10);
      FUN_80247a7c(dVar20,dVar20,dVar20,afStack_10c);
      if (DAT_803dd8b5 == '\0') {
        pfVar15 = (float *)(*(int *)(param_3 + 0x40) + iVar11);
        FUN_80247a48(-(double)*pfVar15,-(double)pfVar15[1],-(double)pfVar15[2],afStack_1bc);
        FUN_80247618(afStack_10c,afStack_1bc,afStack_10c);
        pfVar15 = (float *)(*(int *)(param_3 + 0x40) + iVar11);
        FUN_80247a48((double)*pfVar15,(double)pfVar15[1],(double)pfVar15[2],afStack_1bc);
        FUN_80247618(afStack_1bc,afStack_10c,afStack_10c);
      }
      FUN_80247618(pfVar12,afStack_10c,pfVar12);
      iVar11 = iVar11 + 0x10;
    }
    if (bVar1) {
      FUN_800271c8(piVar8,afStack_14c);
    }
  }
  FUN_8003c270(param_3,piVar8);
  uVar4 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a84(local_200,*(undefined4 *)(param_3 + 0xd4),uVar4,uVar4);
  dVar18 = (double)(FLOAT_803df69c / *(float *)(puVar7 + 4));
  FUN_80247a7c(dVar18,dVar18,dVar18,afStack_10c);
  if (*(int *)(param_3 + 0xa4) != 0) {
    if (((uVar16 == 0) && (uVar3 == 0)) && ((param_4 & 8) == 0)) {
      FUN_80247618(pfVar9,afStack_14c,afStack_cc);
    }
    else {
      uStack_84 = DAT_803dd8c4 + 1U ^ 0x80000000;
      local_88 = 0x43300000;
      dVar18 = (double)(FLOAT_803df69c +
                       (FLOAT_803df6d4 *
                       (float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) -
                                              DOUBLE_803df6c0) * in_f31)) /
                       *(float *)(param_3 + 0x50));
      FUN_80247a48(-(double)*(float *)(param_3 + 0x44),-(double)*(float *)(param_3 + 0x48),
                   -(double)*(float *)(param_3 + 0x4c),afStack_1bc);
      FUN_80247a7c(dVar18,dVar18,dVar18,afStack_10c);
      FUN_80247618(afStack_10c,afStack_1bc,afStack_10c);
      FUN_80247a48((double)*(float *)(param_3 + 0x44),(double)*(float *)(param_3 + 0x48),
                   (double)*(float *)(param_3 + 0x4c),afStack_1bc);
      FUN_80247618(afStack_1bc,afStack_10c,afStack_10c);
      FUN_80247618(afStack_14c,afStack_10c,afStack_1ec);
      FUN_80247618(pfVar9,afStack_1ec,afStack_cc);
    }
    FUN_8025d80c(afStack_cc,(uint)DAT_802cbab1);
    local_c0 = FLOAT_803df684;
    local_b0 = FLOAT_803df684;
    local_a0 = FLOAT_803df684;
    FUN_80247618(afStack_cc,afStack_10c,afStack_cc);
    FUN_8025d848(afStack_cc,(uint)DAT_802cbab1);
    FUN_8025d8c4(afStack_cc,(uint)DAT_802cbabd,0);
  }
  if ((param_4 & 1) == 0) {
    if (uVar3 == 0) {
      FUN_8000fb20();
      FUN_8003dd48();
      if ((*(ushort *)(param_3 + 2) & 0x100) == 0) {
        FUN_80070540();
      }
      else {
        _local_214 = DAT_803dc0c8;
        dVar18 = (double)FLOAT_803df684;
        FUN_8025ca38(dVar18,dVar18,dVar18,dVar18,0,&local_214);
      }
    }
    else {
      FUN_8003d7f0((int)puVar7);
    }
  }
  else {
    FUN_80258944(0);
    FUN_8025ca04(1);
    FUN_8025be54(0);
    FUN_8025c828(0,0xff,0xff,4);
    puVar6 = puVar7;
    do {
      puVar13 = puVar6;
      puVar6 = *(ushort **)(puVar13 + 0x62);
    } while (puVar6 != (ushort *)0x0);
    uVar16 = (uint)*(byte *)(*(int *)(*(int *)(puVar13 + 0x32) + 0xc) + 0x65);
    if (uVar16 == 0xff) {
      local_208 = DAT_803dc0c8;
      FUN_8025c428(3,(byte *)&local_208);
      FUN_8025cce8(0,1,0,5);
    }
    else {
      if (uVar16 < 8) {
        local_204 = (1 << uVar16) << 0x18;
        local_204 = local_204 >> 0x10;
      }
      else {
        local_204 = 1 << uVar16 - 8 & 0xff;
      }
      local_204 = local_204 << 0x10;
      local_204 = CONCAT31(local_204._0_3_,0xff);
      local_20c = local_204;
      FUN_8025c428(3,(byte *)&local_20c);
      FUN_8025cce8(2,1,0,7);
    }
    FUN_8025be80(0);
    FUN_8025c1a4(0,0xf,0xf,0xf,6);
    FUN_8025c224(0,7,7,7,3);
    FUN_8025c65c(0,0,0);
    FUN_8025c2a8(0,0,0,0,1,0);
    FUN_8025c368(0,0,0,0,1,0);
    _local_210 = DAT_803dc0c8;
    dVar18 = (double)FLOAT_803df684;
    FUN_8025ca38(dVar18,dVar18,dVar18,dVar18,0,&local_210);
    FUN_80070434(1);
    FUN_8025c754(7,0,0,7,0);
    FUN_8025a608(4,0,0,1,0,0,2);
    FUN_8025a5bc(1);
    if ((*(byte *)(*(int *)(puVar7 + 0x28) + 0x5f) & 4) == 0) {
      FUN_8007048c(0,3,0);
      FUN_80259288(0);
    }
    else {
      FUN_8007048c(1,3,1);
      FUN_80259288(1);
    }
  }
  FUN_802585d8(9,piVar8[(*(ushort *)(piVar8 + 6) >> 1 & 1) + 7],6);
  if ((*(byte *)(param_3 + 0x24) & 8) == 0) {
    FUN_802585d8(10,piVar8[9],3);
  }
  else {
    FUN_802585d8(10,piVar8[9],9);
  }
  FUN_802585d8(0xb,*(uint *)(param_3 + 0x30),2);
  FUN_802585d8(0xd,*(uint *)(param_3 + 0x34),4);
  FUN_802585d8(0xe,*(uint *)(param_3 + 0x34),4);
  bVar1 = false;
  uVar16 = local_1f0;
  while (local_1f0 = uVar16, !bVar1) {
    puVar17 = (undefined *)(local_200[0] + ((int)local_1f0 >> 3));
    uVar16 = local_1f0 + 4;
    uVar5 = CONCAT12(puVar17[2],CONCAT11(puVar17[1],*puVar17)) >> (local_1f0 & 7);
    uVar2 = uVar5 & 0xf;
    if (uVar2 == 3) {
      local_1f0 = uVar16;
      FUN_8003e6f4(param_3,unaff_r27,unaff_r26,local_200,param_4,local_217,&local_218);
      uVar16 = local_1f0;
    }
    else if (uVar2 < 3) {
      if (uVar2 == 1) {
        uVar3 = param_4 & 0xff;
        if ((((uVar3 == 0) || (uVar3 == 4)) || (uVar3 == 8)) && (DAT_803dd8a0 == '\0')) {
          local_1f0 = uVar16;
          uVar16 = FUN_8003eeec(puVar7,param_3,piVar8,local_200);
          unaff_r27 = FUN_800284e8(param_3,uVar16);
        }
        else {
          puVar17 = (undefined *)(local_200[0] + ((int)uVar16 >> 3));
          local_1f0 = local_1f0 + 10;
          uVar16 = (uint3)(CONCAT12(puVar17[2],CONCAT11(puVar17[1],*puVar17)) >> (uVar16 & 7)) &
                   0x3f;
          unaff_r27 = FUN_800284e8(param_3,uVar16);
        }
        unaff_r26 = (int *)FUN_8002867c((int)piVar8,uVar16);
        uVar16 = local_1f0;
      }
      else if ((uVar5 & 0xf) != 0) {
        if ((((param_4 & 0xff) == 4) || ((param_4 & 0xff) == 8)) && (DAT_803dd8be == '\0')) {
          uVar16 = local_1f0 + 0xc;
        }
        else {
          puVar17 = (undefined *)(local_200[0] + ((int)uVar16 >> 3));
          local_1f0 = local_1f0 + 0xc;
          puVar14 = (undefined4 *)
                    FUN_80028438(param_3,(uint3)(CONCAT12(puVar17[2],CONCAT11(puVar17[1],*puVar17))
                                                >> (uVar16 & 7)) & 0xff);
          FUN_8025d63c(*puVar14,(uint)*(ushort *)(puVar14 + 1));
          uVar16 = local_1f0;
        }
      }
    }
    else if (uVar2 == 5) {
      bVar1 = true;
    }
    else if (uVar2 < 5) {
      local_1f0 = uVar16;
      FUN_8003e2e0(param_3,piVar8,local_200,afStack_10c,pfVar9,(uint)local_217[0],(uint)local_218,
                   param_4 & 1);
      uVar16 = local_1f0;
    }
  }
  FUN_80286864();
  return;
}

