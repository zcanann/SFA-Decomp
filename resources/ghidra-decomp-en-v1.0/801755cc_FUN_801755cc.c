// Function: FUN_801755cc
// Entry: 801755cc
// Size: 2284 bytes

/* WARNING: Removing unreachable block (ram,0x80175e90) */
/* WARNING: Removing unreachable block (ram,0x80175e98) */

void FUN_801755cc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  bool bVar1;
  byte bVar2;
  short sVar3;
  ushort uVar4;
  float fVar5;
  float fVar6;
  undefined4 uVar7;
  undefined uVar8;
  short *psVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  int iVar13;
  float *pfVar14;
  undefined uVar15;
  int iVar16;
  undefined4 uVar17;
  double dVar18;
  double extraout_f1;
  undefined8 in_f30;
  double dVar19;
  undefined8 in_f31;
  undefined8 uVar20;
  undefined auStack432 [4];
  float local_1ac;
  float local_1a8;
  float local_1a4;
  float local_1a0;
  float local_19c;
  float local_198;
  undefined auStack404 [24];
  short local_17c;
  undefined2 local_17a;
  undefined2 local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164 [12];
  float local_134 [12];
  undefined auStack260 [64];
  undefined auStack196 [64];
  float local_84 [4];
  undefined local_74;
  undefined local_70;
  undefined2 local_58;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar20 = FUN_802860d0();
  iVar11 = (int)((ulonglong)uVar20 >> 0x20);
  psVar9 = (short *)uVar20;
  dVar19 = extraout_f1;
  uVar7 = FUN_8002b9ec();
  iVar16 = *(int *)(iVar11 + 0xb8);
  uVar15 = 0;
  iVar10 = 5;
  iVar13 = iVar16 + 0x14;
  while( true ) {
    bVar1 = iVar10 == 0;
    iVar10 = iVar10 + -1;
    if (bVar1) break;
    *(undefined4 *)(iVar13 + 0x114) = *(undefined4 *)(iVar13 + 0x110);
    *(undefined4 *)(iVar13 + 0x128) = *(undefined4 *)(iVar13 + 0x124);
    iVar13 = iVar13 + -4;
  }
  *(undefined4 *)(iVar16 + 0x118) = *(undefined4 *)(iVar11 + 0xc);
  *(undefined4 *)(iVar16 + 300) = *(undefined4 *)(iVar11 + 0x14);
  local_1a0 = *(float *)(psVar9 + 6);
  local_19c = FLOAT_803e359c + *(float *)(psVar9 + 8);
  local_198 = *(float *)(psVar9 + 10);
  local_84[0] = FLOAT_803e35a0;
  local_74 = 0xff;
  local_70 = 3;
  local_58 = 0;
  iVar13 = 0;
  dVar18 = (double)FLOAT_803e3528;
  if (dVar19 <= dVar18) {
    if (param_2 <= dVar18) {
      if (param_2 < dVar18) {
        uStack68 = *(int *)(iVar16 + 0x140) - 0x4000U ^ 0x80000000;
        local_48 = 0x43300000;
        dVar18 = (double)FUN_80293e80((double)((FLOAT_803e3590 *
                                               (float)((double)CONCAT44(0x43300000,uStack68) -
                                                      DOUBLE_803e3578)) / FLOAT_803e3594));
        local_1ac = (float)((double)FLOAT_803e35a4 * dVar18 + (double)local_1a0);
        local_1a8 = local_19c;
        uStack76 = *(int *)(iVar16 + 0x140) - 0x4000U ^ 0x80000000;
        local_50 = 0x43300000;
        dVar18 = (double)FUN_80294204((double)((FLOAT_803e3590 *
                                               (float)((double)CONCAT44(0x43300000,uStack76) -
                                                      DOUBLE_803e3578)) / FLOAT_803e3594));
        local_1a4 = (float)((double)FLOAT_803e35a4 * dVar18 + (double)local_198);
        FUN_8006961c(auStack404,&local_1a0,&local_1ac,local_84,1);
        FUN_800691c0(0,auStack404,0x208,1);
        iVar13 = FUN_80067958(0,&local_1a0,&local_1ac,1,auStack196,8);
        if (iVar13 == 0) {
          iVar13 = FUN_800640cc((double)local_84[0],&local_1a0,&local_1ac,0,0,iVar11,1,0xffffffff,
                                0xff,0);
        }
        if (iVar13 != 0) {
          *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x400;
          fVar5 = FLOAT_803e3528;
          *(float *)(iVar16 + 0x108) = FLOAT_803e3528;
          *(float *)(iVar16 + 0x10c) = fVar5;
        }
      }
    }
    else {
      uStack68 = *(int *)(iVar16 + 0x140) + 0x4000U ^ 0x80000000;
      local_48 = 0x43300000;
      dVar18 = (double)FUN_80293e80((double)((FLOAT_803e3590 *
                                             (float)((double)CONCAT44(0x43300000,uStack68) -
                                                    DOUBLE_803e3578)) / FLOAT_803e3594));
      local_1ac = (float)((double)FLOAT_803e35a4 * dVar18 + (double)local_1a0);
      local_1a8 = local_19c;
      uStack76 = *(int *)(iVar16 + 0x140) + 0x4000U ^ 0x80000000;
      local_50 = 0x43300000;
      dVar18 = (double)FUN_80294204((double)((FLOAT_803e3590 *
                                             (float)((double)CONCAT44(0x43300000,uStack76) -
                                                    DOUBLE_803e3578)) / FLOAT_803e3594));
      local_1a4 = (float)((double)FLOAT_803e35a4 * dVar18 + (double)local_198);
      FUN_8006961c(auStack404,&local_1a0,&local_1ac,local_84,1);
      FUN_800691c0(0,auStack404,0x208,1);
      iVar13 = FUN_80067958(0,&local_1a0,&local_1ac,1,auStack196,8);
      if (iVar13 == 0) {
        iVar13 = FUN_800640cc((double)local_84[0],&local_1a0,&local_1ac,0,0,iVar11,1,0xffffffff,0xff
                              ,0);
      }
      if (iVar13 != 0) {
        *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x800;
        fVar5 = FLOAT_803e3528;
        *(float *)(iVar16 + 0x108) = FLOAT_803e3528;
        *(float *)(iVar16 + 0x10c) = fVar5;
      }
    }
  }
  else {
    uStack76 = *(uint *)(iVar16 + 0x140) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar18 = (double)FUN_80293e80((double)((FLOAT_803e3590 *
                                           (float)((double)CONCAT44(0x43300000,uStack76) -
                                                  DOUBLE_803e3578)) / FLOAT_803e3594));
    local_1ac = (float)((double)FLOAT_803e35a0 * dVar18 + (double)local_1a0);
    local_1a8 = local_19c;
    uStack68 = *(uint *)(iVar16 + 0x140) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar18 = (double)FUN_80294204((double)((FLOAT_803e3590 *
                                           (float)((double)CONCAT44(0x43300000,uStack68) -
                                                  DOUBLE_803e3578)) / FLOAT_803e3594));
    local_1a4 = (float)((double)FLOAT_803e35a0 * dVar18 + (double)local_198);
    FUN_8006961c(auStack404,&local_1a0,&local_1ac,local_84,1);
    FUN_800691c0(0,auStack404,0x208,1);
    iVar13 = FUN_80067958(0,&local_1a0,&local_1ac,1,auStack196,8);
    if (iVar13 == 0) {
      iVar13 = FUN_800640cc((double)local_84[0],&local_1a0,&local_1ac,0,0,iVar11,1,0xffffffff,0xff,0
                           );
    }
    if (iVar13 != 0) {
      *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x200;
      fVar5 = FLOAT_803e3528;
      *(float *)(iVar16 + 0x108) = FLOAT_803e3528;
      *(float *)(iVar16 + 0x10c) = fVar5;
    }
  }
  iVar10 = FUN_80295cd4(uVar7);
  if ((iVar10 == 0) && ((*(byte *)(iVar16 + 0x114) >> 6 & 1) == 0)) {
    iVar13 = 1;
    dVar18 = (double)FLOAT_803e3528;
    if (dVar19 <= dVar18) {
      if (dVar18 <= dVar19) {
        if (param_2 <= dVar18) {
          *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x400;
        }
        else {
          *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x800;
        }
      }
      else {
        *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x100;
      }
    }
    else {
      *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x200;
    }
    fVar5 = FLOAT_803e3528;
    *(float *)(iVar16 + 0x108) = FLOAT_803e3528;
    *(float *)(iVar16 + 0x10c) = fVar5;
  }
  if ((param_5 == 0) || ((*(ushort *)(iVar16 + 0x100) & 8) != 0)) {
    iVar11 = *(int *)(iVar11 + 0x58);
    bVar2 = *(byte *)(iVar11 + 0x10c);
    iVar13 = iVar16;
    for (iVar10 = 0; iVar10 < *(char *)(iVar16 + 0xb4); iVar10 = iVar10 + 1) {
      FUN_800226cc((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                   (double)*(float *)(iVar13 + 0x20),iVar11 + (bVar2 + 2) * 0x40,iVar13 + 0x78,
                   iVar13 + 0x7c,iVar13 + 0x80);
      iVar13 = iVar13 + 0xc;
    }
    goto LAB_80175e18;
  }
  *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 2;
  *(char *)(iVar16 + 0x115) = *(char *)(iVar16 + 0x115) + -1;
  if (*(char *)(iVar16 + 0x115) < '\x01') {
    uVar8 = FUN_800221a0(0x28,0x3c);
    *(undefined *)(iVar16 + 0x115) = uVar8;
    *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) | 0x20;
  }
  fVar5 = FLOAT_803e3528;
  if ((*(ushort *)(iVar16 + 0x100) & 0x80) == 0) {
    if (iVar13 == 0) {
      *(float *)(iVar16 + 0x108) = (float)dVar19;
      *(float *)(iVar16 + 0x10c) = (float)param_2;
    }
  }
  else {
    *(float *)(iVar16 + 0x108) = FLOAT_803e3528;
    *(float *)(iVar16 + 0x10c) = fVar5;
  }
  *(int *)(iVar16 + 0x140) = (int)*psVar9;
  local_17c = *psVar9;
  local_17a = 0;
  local_178 = 0;
  local_174 = FLOAT_803e3588;
  local_170 = FLOAT_803e3528;
  local_16c = FLOAT_803e3528;
  local_168 = FLOAT_803e3528;
  FUN_80021ee8(auStack260,&local_17c);
  FUN_800226cc((double)*(float *)(iVar16 + 0x10c),(double)FLOAT_803e3528,
               (double)*(float *)(iVar16 + 0x108),auStack260,iVar11 + 0x24,auStack432,iVar11 + 0x2c)
  ;
  *(byte *)(iVar16 + 0x114) = *(byte *)(iVar16 + 0x114) & 0x7f | 0x80;
  FUN_8002b95c((double)*(float *)(iVar11 + 0x24),(double)FLOAT_803e3528,
               (double)*(float *)(iVar11 + 0x2c),iVar11);
  FUN_8000e318(iVar11);
  pfVar12 = local_134;
  pfVar14 = local_164;
  iVar13 = iVar16;
  for (iVar10 = 0; iVar10 < *(char *)(iVar16 + 0xb4); iVar10 = iVar10 + 1) {
    FUN_8000e0a0((double)*(float *)(iVar13 + 0x18),(double)*(float *)(iVar13 + 0x1c),
                 (double)*(float *)(iVar13 + 0x20),pfVar12,pfVar12 + 1,pfVar12 + 2,iVar11);
    *pfVar14 = *(float *)(iVar11 + 0xc) - *pfVar12;
    pfVar14[1] = *(float *)(iVar11 + 0x10) - pfVar12[1];
    pfVar14[2] = *(float *)(iVar11 + 0x14) - pfVar12[2];
    pfVar12 = pfVar12 + 3;
    iVar13 = iVar13 + 0xc;
    pfVar14 = pfVar14 + 3;
  }
  if ((*(ushort *)(iVar16 + 0x100) & 4) == 0) {
    FUN_80174bfc(iVar11,iVar16);
  }
  FUN_8000e318(iVar11);
  if ((FLOAT_803e3528 != *(float *)(iVar16 + 0x108)) ||
     (FLOAT_803e3528 != *(float *)(iVar16 + 0x10c))) {
    iVar13 = *(int *)(iVar11 + 0x4c);
    uVar4 = *(ushort *)(*(int *)(iVar11 + 0xb8) + 0x100);
    if ((uVar4 & 1) != 0) {
      *(ushort *)(*(int *)(iVar11 + 0xb8) + 0x100) = uVar4 & 0xfffe;
      iVar10 = (int)*(short *)(iVar13 + 0x18);
      if (-1 < iVar10) {
        sVar3 = *(short *)(iVar11 + 0x46);
        if (sVar3 != 0x411) {
          if (sVar3 < 0x411) {
            if (sVar3 != 0x21e) {
LAB_80175d48:
              if (-1 < *(char *)(iVar13 + 0x23)) {
                FUN_800200e8(iVar10,0);
              }
            }
          }
          else if (sVar3 != 0x7df) goto LAB_80175d48;
        }
      }
    }
  }
  fVar5 = *(float *)(iVar11 + 0xc) - *(float *)(iVar16 + 0x128);
  fVar6 = *(float *)(iVar11 + 0x14) - *(float *)(iVar16 + 0x13c);
  if ((FLOAT_803e3588 < fVar5 * fVar5 + fVar6 * fVar6) &&
     ((*(ushort *)(iVar16 + 0x100) & 0x20) != 0)) {
    FUN_8000bb18(iVar11,100);
    *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) & 0xffdf;
  }
LAB_80175e18:
  uVar4 = *(ushort *)(iVar16 + 0x100);
  if ((uVar4 & 0x100) == 0) {
    if ((uVar4 & 0x200) == 0) {
      if ((uVar4 & 0x400) == 0) {
        if ((uVar4 & 0x800) == 0) {
          if ((uVar4 & 8) != 0) {
            uVar15 = 5;
          }
        }
        else {
          uVar15 = 4;
        }
      }
      else {
        uVar15 = 3;
      }
    }
    else {
      uVar15 = 2;
    }
  }
  else {
    uVar15 = 1;
  }
  *(ushort *)(iVar16 + 0x100) = *(ushort *)(iVar16 + 0x100) & 0xf0ff;
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  FUN_8028611c(uVar15);
  return;
}

