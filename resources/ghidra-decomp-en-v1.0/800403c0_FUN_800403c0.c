// Function: FUN_800403c0
// Entry: 800403c0
// Size: 3160 bytes

/* WARNING: Removing unreachable block (ram,0x80040ff0) */
/* WARNING: Removing unreachable block (ram,0x80040fe0) */
/* WARNING: Removing unreachable block (ram,0x80040fe8) */
/* WARNING: Removing unreachable block (ram,0x80040ff8) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_800403c0(undefined4 param_1,undefined4 param_2,int param_3,uint param_4)

{
  bool bVar1;
  uint3 uVar2;
  uint uVar3;
  uint3 uVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  int iVar8;
  int iVar9;
  undefined4 *puVar10;
  float *pfVar11;
  undefined4 uVar12;
  uint uVar13;
  undefined *puVar14;
  undefined4 unaff_r26;
  undefined4 unaff_r27;
  undefined4 uVar15;
  double dVar16;
  double dVar17;
  undefined8 in_f28;
  double dVar18;
  double dVar19;
  undefined8 in_f29;
  undefined8 in_f30;
  double in_f31;
  undefined8 uVar20;
  undefined local_218;
  undefined local_217 [3];
  undefined4 local_214;
  undefined4 local_210;
  undefined4 local_20c;
  undefined4 local_208;
  int local_204;
  int local_200 [4];
  uint local_1f0;
  undefined auStack492 [48];
  undefined auStack444 [48];
  undefined auStack396 [64];
  undefined auStack332 [64];
  undefined auStack268 [64];
  undefined auStack204 [12];
  float local_c0;
  float local_b0;
  float local_a0;
  undefined4 local_88;
  uint uStack132;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar20 = FUN_802860b4();
  iVar5 = (int)((ulonglong)uVar20 >> 0x20);
  DAT_803dcc2a = 0;
  DAT_803dcc2c = 0;
  DAT_803dcc30 = 0;
  DAT_803dcc34 = 0;
  DAT_803db474 = 0xffffffff;
  DAT_803db478 = 0xff;
  DAT_803db479 = 0xff;
  DAT_803db47c = 0xffffffff;
  DAT_803db480 = 0xff;
  DAT_803db481 = 0xff;
  DAT_803db482 = 0xff;
  DAT_803db484._3_1_ = 0;
  DAT_803db484._2_1_ = 0;
  DAT_803db484._1_1_ = 0;
  DAT_803db484._0_1_ = 0;
  iVar6 = FUN_8002b588();
  uVar7 = FUN_8000f54c();
  if (DAT_803dcc24 == 0) {
    FUN_8002b47c(iVar5,auStack332,0);
  }
  else {
    FUN_80246e80(DAT_803dcc24,auStack332);
    DAT_803dcc24 = 0;
  }
  DAT_803dcc4c = 0;
  if ((*(uint *)(*(int *)(iVar5 + 0x50) + 0x44) & 0x400) != 0) {
    iVar8 = FUN_8002b9ec();
    iVar9 = (**(code **)(*DAT_803dca50 + 0xc))();
    if (((iVar8 != 0) && ((*(ushort *)(iVar8 + 0xb0) & 0x1000) == 0)) &&
       (*(int *)(iVar9 + 0xa4) == iVar8)) {
      dVar18 = (double)(FLOAT_803dea38 +
                       *(float *)(iVar5 + 0xa8) * *(float *)(iVar5 + 8) + *(float *)(iVar5 + 0xa4));
      dVar16 = (double)FUN_8000f480((double)*(float *)(iVar8 + 0x18),
                                    (double)*(float *)(iVar8 + 0x1c),
                                    (double)*(float *)(iVar8 + 0x20));
      if (-dVar16 < dVar18) {
        DAT_803dcc4c = 1;
        FLOAT_803dcc50 = (float)dVar16;
      }
    }
  }
  if (DAT_803dcc28 == '\0') {
    FUN_8008982c(*(undefined *)(iVar5 + 0xf2),&DAT_803dcc54,0x803dcc55,0x803dcc56);
  }
  else {
    DAT_803dcc54._0_1_ = DAT_803dcc58;
    DAT_803dcc54._1_1_ = uRam803dcc59;
    DAT_803dcc54._2_1_ = uRam803dcc5a;
    DAT_803dcc28 = '\0';
  }
  uVar13 = param_4 & 4;
  if ((uVar13 == 0) && ((param_4 & 8) == 0)) {
    if ((param_4 & 2) != 0) {
      in_f31 = (double)FLOAT_803dea50;
    }
  }
  else {
    in_f31 = (double)FLOAT_803dea4c;
  }
  bVar1 = false;
  if ((*(ushort *)(iVar6 + 0x18) & 8) == 0) {
    *(undefined *)(iVar6 + 0x60) = 0;
    FUN_80028544(iVar6);
    if (((*(short *)(param_3 + 0xec) == 0) || ((*(ushort *)(param_3 + 2) & 2) != 0)) ||
       (*(char *)(param_3 + 0xf3) == '\0')) {
      FUN_80028558(iVar6);
      uVar12 = FUN_8002856c(iVar6,0);
      FUN_80246e80(auStack332,uVar12);
    }
    else {
      if (*(int *)(param_3 + 0xa4) == 0) {
        FUN_80028b54(iVar6,param_3,iVar5,auStack332);
      }
      else {
        FUN_80246e54(auStack396);
        FUN_80028b54(iVar6,param_3,iVar5,auStack396);
        if (uVar13 == 0) {
          FUN_800272a8(iVar6,auStack332,&DAT_80342e10);
        }
        else {
          FUN_800271bc(iVar6,&DAT_80342e10);
        }
        bVar1 = true;
      }
      if ((*(code **)(iVar5 + 0x108) != (code *)0x0) && ((int)uVar20 == iVar5)) {
        (**(code **)(iVar5 + 0x108))(iVar5,iVar6,auStack332);
      }
    }
    if (((uVar13 == 0) && ((param_4 & 8) == 0)) || (DAT_803dcc44 == 0)) {
      if (*(char *)(param_3 + 0xf9) != '\0') {
        FUN_80027404(iVar6);
      }
      if (bVar1) {
        if (*(char *)(iVar6 + 0x60) == '\0') {
          uVar12 = *(undefined4 *)(param_3 + 0x28);
        }
        else {
          uVar12 = *(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c);
        }
        FUN_80029ba4(&DAT_80342e10,param_3 + 0x88,uVar12,*(undefined4 *)(iVar6 + 0x40),
                     *(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c));
        FUN_80029834(&DAT_80342e10,param_3 + 0xac,*(undefined4 *)(param_3 + 0x2c),
                     *(undefined4 *)(iVar6 + 0x44),*(byte *)(param_3 + 0x24) & 8);
      }
    }
    if (*(char *)(param_3 + 0xf7) == '\0') {
      iVar8 = *(int *)(iVar5 + 0x54);
      if (iVar8 != 0) {
        *(char *)(iVar8 + 0xaf) = *(char *)(iVar8 + 0xaf) + -1;
        if (*(char *)(*(int *)(iVar5 + 0x54) + 0xaf) < '\0') {
          *(undefined *)(*(int *)(iVar5 + 0x54) + 0xaf) = 0;
        }
      }
    }
    else {
      FUN_80027b40(iVar6,param_3,iVar5,0,(int)uVar20);
    }
    *(ushort *)(iVar6 + 0x18) = *(ushort *)(iVar6 + 0x18) | 8;
  }
  uVar3 = param_4 & 2;
  if (((uVar3 != 0) || (uVar13 != 0)) || ((param_4 & 8) != 0)) {
    iVar9 = 0;
    dVar18 = (double)FLOAT_803dea1c;
    dVar16 = DOUBLE_803dea40;
    for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(param_3 + 0xf3); iVar8 = iVar8 + 1) {
      uStack132 = DAT_803dcc40 ^ 0x80000000;
      local_88 = 0x43300000;
      dVar17 = (double)(float)((double)CONCAT44(0x43300000,uStack132) - dVar16);
      dVar19 = (double)(float)(dVar17 * (double)(float)(in_f31 / (double)*(float *)(*(int *)(param_3
                                                                                            + 0x40)
                                                                                   + iVar9 + 0xc)) +
                              dVar18);
      uVar12 = FUN_8002856c(dVar17,iVar6,iVar8);
      FUN_80247318(dVar19,dVar19,dVar19,auStack268);
      if (DAT_803dcc35 == '\0') {
        pfVar11 = (float *)(*(int *)(param_3 + 0x40) + iVar9);
        FUN_802472e4(-(double)*pfVar11,-(double)pfVar11[1],-(double)pfVar11[2],auStack444);
        FUN_80246eb4(auStack268,auStack444,auStack268);
        pfVar11 = (float *)(*(int *)(param_3 + 0x40) + iVar9);
        FUN_802472e4((double)*pfVar11,(double)pfVar11[1],(double)pfVar11[2],auStack444);
        FUN_80246eb4(auStack444,auStack268,auStack268);
      }
      FUN_80246eb4(uVar12,auStack268,uVar12);
      iVar9 = iVar9 + 0x10;
    }
    if (bVar1) {
      FUN_80027104(iVar6,auStack332);
    }
  }
  FUN_8003c178(param_3,iVar6);
  iVar8 = (uint)*(ushort *)(param_3 + 0xd8) << 3;
  FUN_80013a64(local_200,*(undefined4 *)(param_3 + 0xd4),iVar8,iVar8);
  dVar16 = (double)(FLOAT_803dea1c / *(float *)(iVar5 + 8));
  FUN_80247318(dVar16,dVar16,dVar16,auStack268);
  if (*(int *)(param_3 + 0xa4) != 0) {
    if (((uVar13 == 0) && (uVar3 == 0)) && ((param_4 & 8) == 0)) {
      FUN_80246eb4(uVar7,auStack332,auStack204);
    }
    else {
      uStack132 = DAT_803dcc44 + 1U ^ 0x80000000;
      local_88 = 0x43300000;
      dVar16 = (double)(FLOAT_803dea1c +
                       (FLOAT_803dea54 *
                       (float)((double)(float)((double)CONCAT44(0x43300000,uStack132) -
                                              DOUBLE_803dea40) * in_f31)) /
                       *(float *)(param_3 + 0x50));
      FUN_802472e4(-(double)*(float *)(param_3 + 0x44),-(double)*(float *)(param_3 + 0x48),
                   -(double)*(float *)(param_3 + 0x4c),auStack444);
      FUN_80247318(dVar16,dVar16,dVar16,auStack268);
      FUN_80246eb4(auStack268,auStack444,auStack268);
      FUN_802472e4((double)*(float *)(param_3 + 0x44),(double)*(float *)(param_3 + 0x48),
                   (double)*(float *)(param_3 + 0x4c),auStack444);
      FUN_80246eb4(auStack444,auStack268,auStack268);
      FUN_80246eb4(auStack332,auStack268,auStack492);
      FUN_80246eb4(uVar7,auStack492,auStack204);
    }
    FUN_8025d0a8(auStack204,DAT_802caed9);
    local_c0 = FLOAT_803dea04;
    local_b0 = FLOAT_803dea04;
    local_a0 = FLOAT_803dea04;
    FUN_80246eb4(auStack204,auStack268,auStack204);
    FUN_8025d0e4(auStack204,DAT_802caed9);
    FUN_8025d160(auStack204,DAT_802caee5,0);
  }
  if ((param_4 & 1) == 0) {
    if (uVar3 == 0) {
      FUN_8000fb00();
      FUN_8003dc50(param_3,iVar5);
      if ((*(ushort *)(param_3 + 2) & 0x100) == 0) {
        FUN_800703c4();
      }
      else {
        local_214 = DAT_803db468;
        dVar16 = (double)FLOAT_803dea04;
        FUN_8025c2d4(dVar16,dVar16,dVar16,dVar16,0,&local_214);
      }
    }
    else {
      FUN_8003d6f8(iVar5);
    }
  }
  else {
    FUN_802581e0(0);
    FUN_8025c2a0(1);
    FUN_8025b6f0(0);
    FUN_8025c0c4(0,0xff,0xff,4);
    iVar8 = iVar5;
    do {
      iVar9 = iVar8;
      iVar8 = *(int *)(iVar9 + 0xc4);
    } while (iVar8 != 0);
    uVar13 = (uint)*(byte *)(*(int *)(*(int *)(iVar9 + 100) + 0xc) + 0x65);
    if (uVar13 == 0xff) {
      local_208 = DAT_803db468;
      FUN_8025bcc4(3,&local_208);
      FUN_8025c584(0,1,0,5);
    }
    else {
      if (uVar13 < 8) {
        local_204 = (1 << uVar13) << 0x18;
      }
      else {
        local_204 = (1 << uVar13 - 8 & 0xffU) << 0x10;
      }
      local_204 = CONCAT31(local_204._0_3_,0xff);
      local_20c = local_204;
      FUN_8025bcc4(3,&local_20c);
      FUN_8025c584(2,1,0,7);
    }
    FUN_8025b71c(0);
    FUN_8025ba40(0,0xf,0xf,0xf,6);
    FUN_8025bac0(0,7,7,7,3);
    FUN_8025bef8(0,0,0);
    FUN_8025bb44(0,0,0,0,1,0);
    FUN_8025bc04(0,0,0,0,1,0);
    local_210 = DAT_803db468;
    dVar16 = (double)FLOAT_803dea04;
    FUN_8025c2d4(dVar16,dVar16,dVar16,dVar16,0,&local_210);
    FUN_800702b8(1);
    FUN_8025bff0(7,0,0,7,0);
    FUN_80259ea4(4,0,0,1,0,0,2);
    FUN_80259e58(1);
    if ((*(byte *)(*(int *)(iVar5 + 0x50) + 0x5f) & 4) == 0) {
      FUN_80070310(0,3,0);
      FUN_80258b24(0);
    }
    else {
      FUN_80070310(1,3,1);
      FUN_80258b24(1);
    }
  }
  FUN_80257e74(9,*(undefined4 *)(iVar6 + (*(ushort *)(iVar6 + 0x18) >> 1 & 1) * 4 + 0x1c),6);
  if ((*(byte *)(param_3 + 0x24) & 8) == 0) {
    FUN_80257e74(10,*(undefined4 *)(iVar6 + 0x24),3);
  }
  else {
    FUN_80257e74(10,*(undefined4 *)(iVar6 + 0x24),9);
  }
  FUN_80257e74(0xb,*(undefined4 *)(param_3 + 0x30),2);
  FUN_80257e74(0xd,*(undefined4 *)(param_3 + 0x34),4);
  FUN_80257e74(0xe,*(undefined4 *)(param_3 + 0x34),4);
  bVar1 = false;
  uVar13 = local_1f0;
  while (local_1f0 = uVar13, !bVar1) {
    puVar14 = (undefined *)(local_200[0] + ((int)local_1f0 >> 3));
    uVar13 = local_1f0 + 4;
    uVar4 = CONCAT12(puVar14[2],CONCAT11(puVar14[1],*puVar14)) >> (local_1f0 & 7);
    uVar2 = uVar4 & 0xf;
    if (uVar2 == 3) {
      local_1f0 = uVar13;
      FUN_8003e5fc(param_3,unaff_r27,unaff_r26,local_200,param_4,local_217,&local_218);
      uVar13 = local_1f0;
    }
    else if (uVar2 < 3) {
      if (uVar2 == 1) {
        uVar3 = param_4 & 0xff;
        if ((((uVar3 == 0) || (uVar3 == 4)) || (uVar3 == 8)) && (DAT_803dcc20 == '\0')) {
          local_1f0 = uVar13;
          uVar13 = FUN_8003edf4(iVar5,param_3,iVar6,local_200);
          unaff_r27 = FUN_80028424(param_3,uVar13);
        }
        else {
          puVar14 = (undefined *)(local_200[0] + ((int)uVar13 >> 3));
          local_1f0 = local_1f0 + 10;
          uVar13 = (uint3)(CONCAT12(puVar14[2],CONCAT11(puVar14[1],*puVar14)) >> (uVar13 & 7)) &
                   0x3f;
          unaff_r27 = FUN_80028424(param_3,uVar13);
        }
        unaff_r26 = FUN_800285b8(iVar6,uVar13);
        uVar13 = local_1f0;
      }
      else if ((uVar4 & 0xf) != 0) {
        if ((((param_4 & 0xff) == 4) || ((param_4 & 0xff) == 8)) && (DAT_803dcc3e == '\0')) {
          uVar13 = local_1f0 + 0xc;
        }
        else {
          puVar14 = (undefined *)(local_200[0] + ((int)uVar13 >> 3));
          local_1f0 = local_1f0 + 0xc;
          puVar10 = (undefined4 *)
                    FUN_80028374(param_3,CONCAT12(puVar14[2],CONCAT11(puVar14[1],*puVar14)) >>
                                         (uVar13 & 7) & 0xff);
          FUN_8025ced8(*puVar10,*(undefined2 *)(puVar10 + 1));
          uVar13 = local_1f0;
        }
      }
    }
    else if (uVar2 == 5) {
      bVar1 = true;
    }
    else if (uVar2 < 5) {
      local_1f0 = uVar13;
      FUN_8003e1e8(param_3,iVar6,local_200,auStack268,uVar7,local_217[0],local_218,param_4 & 1);
      uVar13 = local_1f0;
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  FUN_80286100();
  return;
}

