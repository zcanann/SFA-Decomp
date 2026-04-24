// Function: FUN_80090500
// Entry: 80090500
// Size: 2456 bytes

/* WARNING: Removing unreachable block (ram,0x80090e78) */
/* WARNING: Removing unreachable block (ram,0x80090e70) */
/* WARNING: Removing unreachable block (ram,0x80090518) */
/* WARNING: Removing unreachable block (ram,0x80090510) */

void FUN_80090500(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  float *pfVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar8;
  int iVar9;
  undefined8 extraout_f1;
  double dVar10;
  double dVar11;
  double in_f30;
  double dVar12;
  double dVar13;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar14;
  undefined local_188;
  undefined local_187;
  undefined local_186 [2];
  undefined4 local_184;
  undefined4 local_180;
  undefined4 local_17c;
  float local_178;
  float local_174;
  float local_170;
  float local_16c;
  float local_168;
  float local_164;
  float local_160;
  float local_15c;
  float local_158;
  float afStack_154 [16];
  float afStack_114 [16];
  float afStack_d4 [12];
  float local_a4;
  float local_a0;
  float local_94;
  float local_90;
  float local_7c;
  float local_74;
  undefined4 local_70;
  float local_6c;
  float local_68;
  undefined4 local_60;
  uint uStack_5c;
  undefined8 local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar14 = FUN_8028683c();
  uVar2 = (undefined4)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  local_184 = DAT_802c274c;
  local_180 = DAT_802c2750;
  local_17c = DAT_802c2754;
  dVar12 = (double)FLOAT_803dfe24;
  uVar14 = extraout_f1;
  iVar3 = FUN_80008b4c(-1);
  if ((short)iVar3 != 1) {
    iVar3 = 0;
    if (((((((DAT_8039b488 == 0) || (iVar7 != *(int *)(DAT_8039b488 + 0x13f0))) &&
           ((iVar3 = 1, DAT_8039b48c == 0 || (iVar7 != *(int *)(DAT_8039b48c + 0x13f0))))) &&
          ((iVar3 = 2, DAT_8039b490 == 0 || (iVar7 != *(int *)(DAT_8039b490 + 0x13f0))))) &&
         ((iVar3 = 3, DAT_8039b494 == 0 || (iVar7 != *(int *)(DAT_8039b494 + 0x13f0))))) &&
        ((((iVar3 = 4, DAT_8039b498 == 0 || (iVar7 != *(int *)(DAT_8039b498 + 0x13f0))) &&
          ((iVar3 = 5, DAT_8039b49c == 0 || (iVar7 != *(int *)(DAT_8039b49c + 0x13f0))))) &&
         ((iVar3 = 6, DAT_8039b4a0 == 0 || (iVar7 != *(int *)(DAT_8039b4a0 + 0x13f0))))))) &&
       ((iVar3 = 7, DAT_8039b4a4 == 0 || (iVar7 != *(int *)(DAT_8039b4a4 + 0x13f0))))) {
      iVar3 = 8;
    }
    iVar9 = (&DAT_8039b488)[iVar3];
    if ((iVar9 != 0) && (iVar3 != 8)) {
      if (iVar7 == *(int *)(iVar9 + 0x13f0)) {
        uStack_5c = DAT_803dde24 ^ 0x80000000;
        local_60 = 0x43300000;
        DAT_803dde24 = (uint)(FLOAT_803dfe7c * FLOAT_803dc074 +
                             (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803dfe28));
        local_58 = (longlong)(int)DAT_803dde24;
        if (0xffff < (int)DAT_803dde24) {
          DAT_803dde24 = 0;
        }
        dVar12 = (double)(float)(dVar12 * (double)FLOAT_803dfe80);
        FUN_8002191c(dVar12,dVar12,dVar12,afStack_114);
        FUN_800033a8((int)&local_a4,0,0x40);
        local_a4 = FLOAT_803dfe24;
        local_90 = FLOAT_803dfe24;
        local_7c = FLOAT_803dfe24;
        local_68 = FLOAT_803dfe24;
        if ((*(int *)(iVar9 + 0x13f4) == 4) || (*(char *)(iVar9 + 0x1451) == '\0')) {
          if (*(int *)(iVar9 + 0x13f4) == 4) {
            if ((*(byte *)(iVar9 + 0x144a) & 0x80) == 0) {
              if (*(char *)(iVar9 + 0x1451) != '\0') {
                DAT_803dde24 = (uint)(FLOAT_803dfe8c * (*(float *)(iVar9 + 0x1440) / FLOAT_803dfe90)
                                     + FLOAT_803dfe88);
                local_48 = (longlong)(int)DAT_803dde24;
                uStack_4c = -DAT_803dde24 ^ 0x80000000;
                local_50 = 0x43300000;
                dVar12 = (double)FUN_80294964();
                local_a4 = (float)dVar12;
                local_58 = CONCAT44(0x43300000,-DAT_803dde24 ^ 0x80000000);
                dVar12 = (double)FUN_802945e0();
                local_a0 = (float)-dVar12;
                uStack_5c = -DAT_803dde24 ^ 0x80000000;
                local_60 = 0x43300000;
                dVar12 = (double)FUN_802945e0();
                local_94 = (float)dVar12;
                uStack_3c = -DAT_803dde24 ^ 0x80000000;
                local_40 = 0x43300000;
                dVar12 = (double)FUN_80294964();
                local_90 = (float)dVar12;
              }
            }
            else {
              dVar12 = (double)FUN_80294964();
              local_a4 = (float)dVar12;
              dVar12 = (double)FUN_802945e0();
              local_a0 = (float)-dVar12;
              dVar12 = (double)FUN_802945e0();
              local_94 = (float)dVar12;
              dVar12 = (double)FUN_80294964();
              local_90 = (float)dVar12;
            }
          }
        }
        else {
          local_58 = CONCAT44(0x43300000,DAT_803dde24 ^ 0x80000000);
          dVar12 = (double)FUN_80294964();
          local_a4 = (float)dVar12;
          uStack_5c = DAT_803dde24 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar12 = (double)FUN_802945e0();
          local_a0 = (float)-dVar12;
          uStack_4c = DAT_803dde24 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar12 = (double)FUN_802945e0();
          local_94 = (float)dVar12;
          local_48 = CONCAT44(0x43300000,DAT_803dde24 ^ 0x80000000);
          dVar12 = (double)FUN_80294964();
          local_90 = (float)dVar12;
        }
        local_74 = *(float *)(iVar9 + 0x140c) - FLOAT_803dda58;
        local_70 = *(undefined4 *)(iVar9 + 0x1410);
        local_6c = *(float *)(iVar9 + 0x1414) - FLOAT_803dda5c;
        FUN_800223a8(afStack_114,&local_a4,afStack_154);
        FUN_800216cc(afStack_154,afStack_d4);
        pfVar4 = (float *)FUN_8000f56c();
        FUN_80247618(pfVar4,afStack_d4,afStack_d4);
        FUN_8025d80c(afStack_d4,0);
        uVar8 = 0;
        iVar3 = DAT_803dde44;
        if (*(int *)(iVar9 + 0x13f4) == 0) {
          iVar3 = DAT_8039b478;
        }
        FUN_8004c460(iVar3,0);
        FUN_80259288(0);
        FUN_80079b3c();
        FUN_80079764();
        FUN_80079980();
        if (*(int *)(iVar9 + 0x13f4) == 4) {
          FUN_8005d294(uVar2,0x7d,0x7d,0x9b,0xff);
        }
        else if (*(int *)(iVar9 + 0x13f4) == 0) {
          FUN_80089b54(0,local_186,&local_187,&local_188);
          FUN_8005d294(uVar2,local_186[0],local_187,local_188,0xff);
        }
        FUN_80078cc8();
        FUN_80257b5c();
        FUN_802570dc(0,1);
        FUN_802570dc(9,1);
        FUN_802570dc(0xb,1);
        FUN_802570dc(0xd,1);
        FUN_8025d888(0);
        FUN_80257b5c();
        FUN_802570dc(9,1);
        FUN_802570dc(0xd,1);
        uVar5 = FUN_80020800();
        dVar10 = (double)(FLOAT_803dfe64 * (*(float *)(iVar9 + 0x13e4) - *(float *)(iVar9 + 0x13d8))
                         );
        dVar12 = (double)(FLOAT_803dfe94 * *(float *)(iVar9 + 0x1378));
        if ((dVar12 <= dVar10) &&
           (dVar11 = (double)(FLOAT_803dfe94 * *(float *)(iVar9 + 0x1390)), dVar12 = dVar10,
           dVar11 < dVar10)) {
          dVar12 = dVar11;
        }
        dVar11 = (double)(FLOAT_803dfe64 * (*(float *)(iVar9 + 0x13ec) - *(float *)(iVar9 + 0x13e0))
                         );
        dVar10 = (double)(FLOAT_803dfe94 * *(float *)(iVar9 + 0x1380));
        if ((dVar10 <= dVar11) &&
           (dVar13 = (double)(FLOAT_803dfe94 * *(float *)(iVar9 + 0x13b0)), dVar10 = dVar11,
           dVar13 < dVar11)) {
          dVar10 = dVar13;
        }
        if (*(int *)(iVar9 + 0x13f4) == 4) {
          FUN_80259000(0x90,4,*(int *)(iVar9 + 0x13fc) * 3 & 0xffff);
        }
        else {
          uVar6 = *(int *)(iVar9 + 0x13fc) * 3;
          FUN_80259000(0x90,4,((int)uVar6 >> 2) + (uint)((int)uVar6 < 0 && (uVar6 & 3) != 0) &
                              0xffff);
        }
        pfVar4 = *(float **)(iVar9 + 4);
        for (iVar3 = 0; iVar3 < *(int *)(iVar9 + 0x13fc); iVar3 = iVar3 + 1) {
          uVar6 = (uint)*(byte *)((int)pfVar4 + 0x16);
          if (uVar6 != uVar8) {
            FUN_8004c460((&DAT_8039b478)[uVar6],0);
            uVar8 = *(int *)(iVar9 + 0x13fc) * 3;
            FUN_80259000(0x90,4,((int)uVar8 >> 2) + (uint)((int)uVar8 < 0 && (uVar8 & 3) != 0) &
                                0xffff);
            uVar8 = uVar6;
          }
          if ((uVar5 & 0xff) == 0) {
            if (*(char *)(iVar9 + 0x144d) == '\0') {
              *pfVar4 = (float)((double)*pfVar4 + dVar12);
              pfVar4[2] = (float)((double)pfVar4[2] + dVar10);
            }
            *pfVar4 = *(float *)(iVar9 + 0x1420) * FLOAT_803dc074 + *pfVar4;
            pfVar4[2] = *(float *)(iVar9 + 0x1424) * FLOAT_803dc074 + pfVar4[2];
            fVar1 = *pfVar4;
            if (*(float *)(iVar9 + 0x1378) <= fVar1) {
              if (*(float *)(iVar9 + 0x1390) < fVar1) {
                *pfVar4 = -(FLOAT_803dfe48 * *(float *)(iVar9 + 0x1390) - fVar1);
              }
            }
            else {
              *pfVar4 = FLOAT_803dfe48 * *(float *)(iVar9 + 0x1390) + fVar1;
            }
            fVar1 = pfVar4[2];
            if (*(float *)(iVar9 + 0x1380) <= fVar1) {
              if (*(float *)(iVar9 + 0x13b0) < fVar1) {
                pfVar4[2] = -(FLOAT_803dfe48 * *(float *)(iVar9 + 0x13b0) - fVar1);
              }
            }
            else {
              pfVar4[2] = FLOAT_803dfe48 * *(float *)(iVar9 + 0x13b0) + fVar1;
            }
          }
          local_164 = pfVar4[1] - *(float *)(iVar9 + (uint)*(ushort *)(pfVar4 + 4) * 4 + 8);
          iVar7 = (uint)*(ushort *)((int)pfVar4 + 0x12) * 0x2c;
          fVar1 = pfVar4[3];
          local_158 = *pfVar4;
          local_160 = *(float *)(iVar9 + iVar7 + 0x1008) * fVar1 + local_158;
          local_16c = *(float *)(iVar9 + iVar7 + 0x1014) * fVar1 + local_164;
          local_170 = pfVar4[2];
          local_178 = *(float *)(iVar9 + iVar7 + 0x1020) * fVar1 + local_170;
          local_15c = *(float *)(iVar9 + iVar7 + 0x100c) * fVar1 + local_158;
          local_168 = *(float *)(iVar9 + iVar7 + 0x1018) * fVar1 + local_164;
          local_174 = *(float *)(iVar9 + iVar7 + 0x1024) * fVar1 + local_170;
          local_158 = *(float *)(iVar9 + iVar7 + 0x1010) * fVar1 + local_158;
          local_164 = *(float *)(iVar9 + iVar7 + 0x101c) * fVar1 + local_164;
          local_170 = *(float *)(iVar9 + iVar7 + 0x1028) * fVar1 + local_170;
          DAT_cc008000 = local_160;
          DAT_cc008000 = local_16c;
          DAT_cc008000 = local_178;
          DAT_cc008000._0_2_ = local_184._0_2_;
          DAT_cc008000._0_2_ = local_184._2_2_;
          DAT_cc008000 = local_15c;
          DAT_cc008000 = local_168;
          DAT_cc008000 = local_174;
          DAT_cc008000._0_2_ = local_180._0_2_;
          DAT_cc008000._0_2_ = local_180._2_2_;
          DAT_cc008000 = local_158;
          DAT_cc008000 = local_164;
          DAT_cc008000 = local_170;
          DAT_cc008000._0_2_ = local_17c._0_2_;
          DAT_cc008000._0_2_ = local_17c._2_2_;
          pfVar4 = pfVar4 + 6;
        }
      }
      else {
        FUN_80137c30(uVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_____Error_non_existant_cloud_id___803101f0,iVar7,iVar3,in_r6,in_r7,in_r8,
                     in_r9,in_r10);
      }
    }
  }
  FUN_80286888();
  return;
}

