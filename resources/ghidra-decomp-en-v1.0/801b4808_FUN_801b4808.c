// Function: FUN_801b4808
// Entry: 801b4808
// Size: 2124 bytes

/* WARNING: Removing unreachable block (ram,0x801b4df4) */
/* WARNING: Removing unreachable block (ram,0x801b5034) */

void FUN_801b4808(void)

{
  char cVar1;
  byte bVar2;
  short sVar3;
  int iVar4;
  undefined4 uVar5;
  float fVar6;
  float fVar7;
  uint uVar8;
  int iVar9;
  float *pfVar10;
  int iVar11;
  float *pfVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined local_e8;
  undefined local_e7;
  undefined local_e6;
  float local_e4;
  float local_e0;
  float local_dc;
  short local_d8;
  short local_d6;
  short local_d4;
  short local_d2;
  short local_d0;
  short local_ce;
  undefined auStack204 [48];
  undefined auStack156 [8];
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined4 local_40;
  uint uStack60;
  double local_38;
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_802860d8();
  pfVar10 = *(float **)(iVar4 + 0xb8);
  DAT_803ddb58 = DAT_803ddb58 + 1;
  pfVar10[0x293] = (float)((int)pfVar10[0x293] + (uint)DAT_803db410);
  pfVar12 = pfVar10;
  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(pfVar10 + 0x296); iVar11 = iVar11 + 1) {
    pfVar12[4] = (float)((int)pfVar12[4] + (uint)DAT_803db410);
    if (*(char *)((int)pfVar12 + 0x2f) != '\0') {
      dVar15 = (double)pfVar12[7];
      uStack92 = (uint)pfVar12[5] ^ 0x80000000;
      local_60 = 0x43300000;
      uStack84 = (uint)pfVar12[4] ^ 0x80000000;
      local_58 = 0x43300000;
      local_50 = 0x43300000;
      uStack76 = uStack92;
      dVar14 = (double)FUN_80291dd8((double)((FLOAT_803e4934 *
                                             ((float)((double)CONCAT44(0x43300000,uStack92) -
                                                     DOUBLE_803e4948) -
                                             (float)((double)CONCAT44(0x43300000,uStack84) -
                                                    DOUBLE_803e4948))) /
                                            (float)((double)CONCAT44(0x43300000,uStack92) -
                                                   DOUBLE_803e4948)));
      pfVar12[3] = -(float)((double)FLOAT_803ddb70 *
                            (double)(float)((double)(float)(dVar15 - (double)pfVar12[6]) * dVar14) -
                           dVar15);
      local_48 = (double)CONCAT44(0x43300000,(uint)pfVar12[4] ^ 0x80000000);
      uStack60 = (uint)pfVar12[5] ^ 0x80000000;
      local_40 = 0x43300000;
      dVar14 = (double)FUN_80291dd8((double)((FLOAT_803e493c * (float)(local_48 - DOUBLE_803e4948))
                                            / (float)((double)CONCAT44(0x43300000,uStack60) -
                                                     DOUBLE_803e4948)));
      iVar9 = (int)-(float)((double)FLOAT_803ddb6c *
                            (double)(float)((double)FLOAT_803e4938 * dVar14) -
                           (double)FLOAT_803e4938);
      local_38 = (double)(longlong)iVar9;
      *(char *)((int)pfVar12 + 0x2e) = (char)iVar9;
      if ((int)pfVar12[4] < (int)pfVar12[5]) {
        *(ushort *)(pfVar12 + 10) =
             *(short *)(pfVar12 + 10) + (ushort)DAT_803db410 * *(short *)((int)pfVar12 + 0x2a);
        if (3 < *(byte *)(pfVar12 + 0xb)) {
          *(byte *)(pfVar12 + 0xb) = *(byte *)(pfVar12 + 0xb) - 4;
        }
        if (*(byte *)((int)pfVar12 + 0x2d) < 5) {
          local_38 = (double)CONCAT44(0x43300000,(uint)pfVar12[4] ^ 0x80000000);
          uStack60 = (uint)pfVar12[5] ^ 0x80000000;
          local_40 = 0x43300000;
          if (((float)(local_38 - DOUBLE_803e4948) /
               (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4948) < FLOAT_803e4998) &&
             (pfVar12[8] = (float)((int)pfVar12[8] - (uint)DAT_803db410), (int)pfVar12[8] < 1)) {
            cVar1 = *(char *)((int)pfVar12 + 0x2d);
            dVar14 = (double)pfVar12[7];
            iVar9 = *(int *)(iVar4 + 0xb8);
            uVar8 = FUN_800221a0(0xfffffffb,3);
            local_38 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            local_e4 = pfVar12[3] *
                       (FLOAT_803e495c * (float)(local_38 - DOUBLE_803e4948) + FLOAT_803e492c);
            local_e0 = FLOAT_803e4960;
            local_dc = FLOAT_803e4960;
            uStack60 = FUN_800221a0(0,0xffff);
            uStack60 = uStack60 ^ 0x80000000;
            local_40 = 0x43300000;
            FUN_802470c8((double)(float)(DOUBLE_803e4968 *
                                        (double)((float)((double)CONCAT44(0x43300000,uStack60) -
                                                        DOUBLE_803e4948) / FLOAT_803e4970)),
                         auStack204,0x7a);
            uVar5 = FUN_8000f540();
            FUN_80246eb4(uVar5,auStack204,auStack204);
            FUN_80247574(auStack204,&local_e4,&local_e4);
            local_e4 = local_e4 + *pfVar12;
            local_e0 = local_e0 + pfVar12[1];
            local_dc = local_dc + pfVar12[2];
            uVar8 = FUN_800221a0(0xc0,0x100);
            local_48 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000);
            if (*(byte *)(iVar9 + 0xa58) < 0x32) {
              FUN_801b3de4((double)((float)(dVar14 * (double)(float)(local_48 - DOUBLE_803e4948)) *
                                   FLOAT_803e4974),(double)local_e4,(double)local_e0,
                           (double)local_dc,iVar4,cVar1 + '\x01');
            }
            pfVar12[8] = pfVar12[9];
          }
        }
      }
      else {
        *(undefined *)((int)pfVar12 + 0x2f) = 0;
      }
    }
    pfVar12 = pfVar12 + 0xc;
  }
  FUN_80003494(auStack156,iVar4,0x38);
  local_94 = FLOAT_803e492c;
  local_78 = FLOAT_803e4960;
  local_74 = FLOAT_803e4960;
  local_70 = FLOAT_803e4960;
  pfVar12 = pfVar10;
  for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)((int)pfVar10 + 0xa5a); iVar11 = iVar11 + 1) {
    if (*(char *)(pfVar12 + 0x261) != '\0') {
      pfVar12[0x25f] = (float)((int)pfVar12[0x25f] + (uint)DAT_803db410);
      dVar14 = DOUBLE_803e4990;
      if ((int)pfVar12[0x25f] < (int)pfVar12[0x260]) {
        fVar6 = pfVar10[0x28f];
        uVar8 = (uint)DAT_803db410;
        local_38 = (double)CONCAT44(0x43300000,uVar8);
        dVar15 = local_38 - DOUBLE_803e4990;
        uStack60 = uVar8 * uVar8 ^ 0x80000000;
        local_40 = 0x43300000;
        local_48 = (double)CONCAT44(0x43300000,uVar8);
        pfVar12[0x25a] =
             -(FLOAT_803e499c *
               fVar6 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4948) -
              (pfVar12[0x25d] * (float)(local_48 - DOUBLE_803e4990) + pfVar12[0x25a]));
        pfVar12[0x25d] = -(fVar6 * (float)dVar15 - pfVar12[0x25d]);
        uStack76 = (uint)DAT_803db410;
        local_50 = 0x43300000;
        pfVar12[0x259] =
             pfVar12[0x25c] * (float)((double)CONCAT44(0x43300000,uStack76) - dVar14) +
             pfVar12[0x259];
        uStack84 = (uint)DAT_803db410;
        local_58 = 0x43300000;
        pfVar12[0x25b] =
             pfVar12[0x25e] * (float)((double)CONCAT44(0x43300000,uStack84) - dVar14) +
             pfVar12[0x25b];
        if (((*(char *)(pfVar10 + 0x297) != '\0') && (pfVar12[0x25a] < pfVar10[600])) &&
           (pfVar12[0x25d] < FLOAT_803e4960)) {
          pfVar12[0x25d] = FLOAT_803e49a0 * -pfVar12[0x25d];
        }
        local_90 = pfVar12[0x259];
        local_8c = pfVar12[0x25a];
        local_88 = pfVar12[0x25b];
        local_84 = local_90;
        local_80 = local_8c;
        local_7c = local_88;
        if ((DAT_803ddb58 & 1) != 0) {
          fVar6 = pfVar12[0x25f];
          if ((int)fVar6 < 0x40) {
            local_d0 = (short)((int)fVar6 << 6);
            local_d8 = -1 - local_d0;
            local_d4 = -0x8000;
            local_d2 = -0x4000 - local_d0;
            local_d0 = -0x6000 - local_d0;
            local_d6 = local_d8;
          }
          else if ((int)fVar6 < 0x80) {
            local_d6 = (short)((int)fVar6 << 6);
            local_d8 = -0x4000 - local_d6;
            local_d6 = -0x6000 - local_d6;
            local_d4 = 0;
            local_d2 = -0x8000;
            local_d0 = 0;
          }
          else {
            local_d8 = -0x6000;
            local_d6 = 0;
            local_d4 = 0;
            local_d2 = 0;
            local_d0 = 0;
          }
          sVar3 = local_d4;
          local_ce = 0;
          bVar2 = *(byte *)((int)pfVar10 + 0xa5d);
          if (bVar2 == 2) {
            local_d6 = local_d8;
            local_d0 = local_d2;
            local_d8 = local_d4;
            local_d2 = 0;
          }
          else if (bVar2 < 2) {
            if (bVar2 != 0) {
              local_d6 = local_d4;
              local_d0 = 0;
            }
          }
          else if (bVar2 < 4) {
            local_d6 = local_d4;
            local_d0 = 0;
            local_d4 = local_d8;
            local_ce = local_d2;
            local_d8 = sVar3;
            local_d2 = 0;
          }
          (**(code **)(*DAT_803dca88 + 8))(iVar4,0x5e,auStack156,0x200001,0xffffffff,&local_d8);
        }
      }
      else {
        *(undefined *)(pfVar12 + 0x261) = 0;
      }
    }
    pfVar12 = pfVar12 + 9;
  }
  fVar6 = pfVar10[0x293];
  fVar7 = pfVar10[0x294];
  if ((int)fVar7 << 1 < (int)fVar6) {
    FUN_8002cbc4(iVar4);
  }
  else {
    if ((int)fVar7 < (int)fVar6) {
      if (pfVar10[0x290] != 0.0) {
        FUN_8001db6c((double)FLOAT_803e4960,pfVar10[0x290],0);
      }
    }
    else {
      local_38 = (double)CONCAT44(0x43300000,(uint)fVar6 ^ 0x80000000);
      uStack60 = (uint)fVar7 ^ 0x80000000;
      local_40 = 0x43300000;
      FUN_801b40b8((double)(float)(local_38 - DOUBLE_803e4948),
                   (double)(float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4948),
                   *(undefined *)((int)pfVar10 + 0xa5d),&local_e8);
      if (pfVar10[0x290] != 0.0) {
        FUN_8001daf0(pfVar10[0x290],local_e8,local_e7,local_e6,0xff);
      }
    }
    local_38 = (double)CONCAT44(0x43300000,(uint)pfVar10[0x293] ^ 0x80000000);
    uStack60 = (uint)pfVar10[0x294] ^ 0x80000000;
    local_40 = 0x43300000;
    fVar6 = (float)(local_38 - DOUBLE_803e4948) /
            (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4948);
    *(float *)(iVar4 + 8) = FLOAT_803e49a4 * fVar6 * pfVar10[0x295];
    iVar11 = (int)-(FLOAT_803e4938 * fVar6 - FLOAT_803e4938);
    local_48 = (double)(longlong)iVar11;
    *(char *)(iVar4 + 0x36) = (char)iVar11;
    if ((*(char *)((int)pfVar10 + 0xa5b) == '\0') &&
       ((int)pfVar10[0x294] >> 1 <= (int)pfVar10[0x293])) {
      local_d8 = FUN_800221a0(0x1000,0x6000);
      local_d2 = SUB42(pfVar10[5],0);
      uVar8 = 0;
      while (local_38 = (double)CONCAT44(0x43300000,uVar8 ^ 0x80000000),
            (float)(local_38 - DOUBLE_803e4948) < pfVar10[0x295]) {
        uVar8 = uVar8 + 1;
      }
      *(undefined *)((int)pfVar10 + 0xa5b) = 1;
      local_d6 = local_d8;
      local_d4 = local_d8;
    }
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286124();
  return;
}

