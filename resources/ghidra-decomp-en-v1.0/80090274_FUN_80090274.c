// Function: FUN_80090274
// Entry: 80090274
// Size: 2456 bytes

/* WARNING: Removing unreachable block (ram,0x80090be4) */
/* WARNING: Removing unreachable block (ram,0x80090bec) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80090274(void)

{
  float fVar1;
  undefined4 uVar2;
  short sVar5;
  undefined4 uVar3;
  char cVar6;
  uint uVar4;
  int iVar7;
  uint uVar8;
  int iVar9;
  float *pfVar10;
  int iVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f30;
  double dVar15;
  double dVar16;
  undefined8 in_f31;
  undefined8 uVar17;
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
  undefined auStack340 [64];
  undefined auStack276 [64];
  undefined auStack212 [48];
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
  uint uStack92;
  double local_58;
  undefined4 local_50;
  uint uStack76;
  double local_48;
  undefined4 local_40;
  uint uStack60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar17 = FUN_802860d8();
  uVar2 = (undefined4)((ulonglong)uVar17 >> 0x20);
  iVar9 = (int)uVar17;
  local_184 = DAT_802c1fcc;
  local_180 = DAT_802c1fd0;
  local_17c = DAT_802c1fd4;
  dVar15 = (double)FLOAT_803df1a4;
  sVar5 = FUN_80008b4c(0xffffffff);
  if (sVar5 != 1) {
    iVar7 = 0;
    if (((((((DAT_8039a828 == 0) || (iVar9 != *(int *)(DAT_8039a828 + 0x13f0))) &&
           ((iVar7 = 1, DAT_8039a82c == 0 || (iVar9 != *(int *)(DAT_8039a82c + 0x13f0))))) &&
          ((iVar7 = 2, DAT_8039a830 == 0 || (iVar9 != *(int *)(DAT_8039a830 + 0x13f0))))) &&
         ((iVar7 = 3, DAT_8039a834 == 0 || (iVar9 != *(int *)(DAT_8039a834 + 0x13f0))))) &&
        ((((iVar7 = 4, DAT_8039a838 == 0 || (iVar9 != *(int *)(DAT_8039a838 + 0x13f0))) &&
          ((iVar7 = 5, DAT_8039a83c == 0 || (iVar9 != *(int *)(DAT_8039a83c + 0x13f0))))) &&
         ((iVar7 = 6, DAT_8039a840 == 0 || (iVar9 != *(int *)(DAT_8039a840 + 0x13f0))))))) &&
       ((iVar7 = 7, DAT_8039a844 == 0 || (iVar9 != *(int *)(DAT_8039a844 + 0x13f0))))) {
      iVar7 = 8;
    }
    iVar11 = (&DAT_8039a828)[iVar7];
    if ((iVar11 != 0) && (iVar7 != 8)) {
      if (iVar9 == *(int *)(iVar11 + 0x13f0)) {
        uStack92 = DAT_803dd1a4 ^ 0x80000000;
        local_60 = 0x43300000;
        DAT_803dd1a4 = (uint)(FLOAT_803df1fc * FLOAT_803db414 +
                             (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df1a8));
        local_58 = (double)(longlong)(int)DAT_803dd1a4;
        if (0xffff < (int)DAT_803dd1a4) {
          DAT_803dd1a4 = 0;
        }
        dVar15 = (double)(float)(dVar15 * (double)FLOAT_803df200);
        FUN_80021858(dVar15,dVar15,dVar15,auStack276);
        FUN_800033a8(&local_a4,0,0x40);
        local_a4 = FLOAT_803df1a4;
        local_90 = FLOAT_803df1a4;
        local_7c = FLOAT_803df1a4;
        local_68 = FLOAT_803df1a4;
        if ((*(int *)(iVar11 + 0x13f4) == 4) || (*(char *)(iVar11 + 0x1451) == '\0')) {
          if (*(int *)(iVar11 + 0x13f4) == 4) {
            if ((*(byte *)(iVar11 + 0x144a) & 0x80) == 0) {
              if (*(char *)(iVar11 + 0x1451) != '\0') {
                DAT_803dd1a4 = (uint)(FLOAT_803df20c *
                                      (*(float *)(&DAT_00001440 + iVar11) / FLOAT_803df210) +
                                     FLOAT_803df208);
                local_48 = (double)(longlong)(int)DAT_803dd1a4;
                uStack76 = -DAT_803dd1a4 ^ 0x80000000;
                local_50 = 0x43300000;
                dVar15 = (double)FUN_80294204((double)((FLOAT_803df1f0 *
                                                       (float)((double)CONCAT44(0x43300000,uStack76)
                                                              - DOUBLE_803df1a8)) / FLOAT_803df1f4))
                ;
                local_a4 = (float)dVar15;
                local_58 = (double)CONCAT44(0x43300000,-DAT_803dd1a4 ^ 0x80000000);
                dVar15 = (double)FUN_80293e80((double)((FLOAT_803df1f0 *
                                                       (float)(local_58 - DOUBLE_803df1a8)) /
                                                      FLOAT_803df1f4));
                local_a0 = (float)-dVar15;
                uStack92 = -DAT_803dd1a4 ^ 0x80000000;
                local_60 = 0x43300000;
                dVar15 = (double)FUN_80293e80((double)((FLOAT_803df1f0 *
                                                       (float)((double)CONCAT44(0x43300000,uStack92)
                                                              - DOUBLE_803df1a8)) / FLOAT_803df1f4))
                ;
                local_94 = (float)dVar15;
                uStack60 = -DAT_803dd1a4 ^ 0x80000000;
                local_40 = 0x43300000;
                dVar15 = (double)FUN_80294204((double)((FLOAT_803df1f0 *
                                                       (float)((double)CONCAT44(0x43300000,uStack60)
                                                              - DOUBLE_803df1a8)) / FLOAT_803df1f4))
                ;
                local_90 = (float)dVar15;
              }
            }
            else {
              dVar15 = (double)FUN_80294204((double)FLOAT_803df204);
              local_a4 = (float)dVar15;
              dVar15 = (double)FUN_80293e80((double)FLOAT_803df204);
              local_a0 = (float)-dVar15;
              dVar15 = (double)FUN_80293e80((double)FLOAT_803df204);
              local_94 = (float)dVar15;
              dVar15 = (double)FUN_80294204((double)FLOAT_803df204);
              local_90 = (float)dVar15;
            }
          }
        }
        else {
          local_58 = (double)CONCAT44(0x43300000,DAT_803dd1a4 ^ 0x80000000);
          dVar15 = (double)FUN_80294204((double)((FLOAT_803df1f0 *
                                                 (float)(local_58 - DOUBLE_803df1a8)) /
                                                FLOAT_803df1f4));
          local_a4 = (float)dVar15;
          uStack92 = DAT_803dd1a4 ^ 0x80000000;
          local_60 = 0x43300000;
          dVar15 = (double)FUN_80293e80((double)((FLOAT_803df1f0 *
                                                 (float)((double)CONCAT44(0x43300000,uStack92) -
                                                        DOUBLE_803df1a8)) / FLOAT_803df1f4));
          local_a0 = (float)-dVar15;
          uStack76 = DAT_803dd1a4 ^ 0x80000000;
          local_50 = 0x43300000;
          dVar15 = (double)FUN_80293e80((double)((FLOAT_803df1f0 *
                                                 (float)((double)CONCAT44(0x43300000,uStack76) -
                                                        DOUBLE_803df1a8)) / FLOAT_803df1f4));
          local_94 = (float)dVar15;
          local_48 = (double)CONCAT44(0x43300000,DAT_803dd1a4 ^ 0x80000000);
          dVar15 = (double)FUN_80294204((double)((FLOAT_803df1f0 *
                                                 (float)(local_48 - DOUBLE_803df1a8)) /
                                                FLOAT_803df1f4));
          local_90 = (float)dVar15;
        }
        local_74 = *(float *)(iVar11 + 0x140c) - FLOAT_803dcdd8;
        local_70 = *(undefined4 *)(iVar11 + 0x1410);
        local_6c = *(float *)(iVar11 + 0x1414) - FLOAT_803dcddc;
        FUN_800222e4(auStack276,&local_a4,auStack340);
        FUN_80021608(auStack340,auStack212);
        uVar3 = FUN_8000f54c();
        FUN_80246eb4(uVar3,auStack212,auStack212);
        FUN_8025d0a8(auStack212,0);
        uVar8 = 0;
        uVar3 = DAT_803dd1c4;
        if (*(int *)(iVar11 + 0x13f4) == 0) {
          uVar3 = DAT_8039a818;
        }
        FUN_8004c2e4(uVar3,0);
        FUN_80258b24(0);
        FUN_800799c0();
        FUN_800795e8();
        FUN_80079804();
        if (*(int *)(iVar11 + 0x13f4) == 4) {
          FUN_8005d118(uVar2,0x7d,0x7d,0x9b,0xff);
        }
        else if (*(int *)(iVar11 + 0x13f4) == 0) {
          FUN_800898c8(0,local_186,&local_187,&local_188);
          FUN_8005d118(uVar2,local_186[0],local_187,local_188,0xff);
        }
        FUN_80078b4c();
        FUN_802573f8();
        FUN_80256978(0,1);
        FUN_80256978(9,1);
        FUN_80256978(0xb,1);
        FUN_80256978(0xd,1);
        FUN_8025d124(0);
        FUN_802573f8();
        FUN_80256978(9,1);
        FUN_80256978(0xd,1);
        cVar6 = FUN_8002073c();
        dVar13 = (double)(FLOAT_803df1e4 *
                         (*(float *)(iVar11 + 0x13e4) - *(float *)(iVar11 + 0x13d8)));
        dVar15 = (double)(FLOAT_803df214 * *(float *)(iVar11 + 0x1378));
        if ((dVar15 <= dVar13) &&
           (dVar14 = (double)(FLOAT_803df214 * *(float *)(iVar11 + 0x1390)), dVar15 = dVar13,
           dVar14 < dVar13)) {
          dVar15 = dVar14;
        }
        dVar14 = (double)(FLOAT_803df1e4 *
                         (*(float *)(iVar11 + 0x13ec) - *(float *)(iVar11 + 0x13e0)));
        dVar13 = (double)(FLOAT_803df214 * *(float *)(iVar11 + 0x1380));
        if ((dVar13 <= dVar14) &&
           (dVar16 = (double)(FLOAT_803df214 * *(float *)(iVar11 + 0x13b0)), dVar13 = dVar14,
           dVar16 < dVar14)) {
          dVar13 = dVar16;
        }
        if (*(int *)(iVar11 + 0x13f4) == 4) {
          FUN_8025889c(0x90,4,*(int *)(iVar11 + 0x13fc) * 3 & 0xffff);
        }
        else {
          uVar4 = *(int *)(iVar11 + 0x13fc) * 3;
          FUN_8025889c(0x90,4,((int)uVar4 >> 2) + (uint)((int)uVar4 < 0 && (uVar4 & 3) != 0) &
                              0xffff);
        }
        pfVar10 = *(float **)(iVar11 + 4);
        for (iVar9 = 0; iVar9 < *(int *)(iVar11 + 0x13fc); iVar9 = iVar9 + 1) {
          uVar4 = (uint)*(byte *)((int)pfVar10 + 0x16);
          if (uVar4 != uVar8) {
            FUN_8004c2e4((&DAT_8039a818)[uVar4],0);
            uVar8 = *(int *)(iVar11 + 0x13fc) * 3;
            FUN_8025889c(0x90,4,((int)uVar8 >> 2) + (uint)((int)uVar8 < 0 && (uVar8 & 3) != 0) &
                                0xffff);
            uVar8 = uVar4;
          }
          if (cVar6 == '\0') {
            if (*(char *)(iVar11 + 0x144d) == '\0') {
              *pfVar10 = (float)((double)*pfVar10 + dVar15);
              pfVar10[2] = (float)((double)pfVar10[2] + dVar13);
            }
            *pfVar10 = *(float *)(iVar11 + 0x1420) * FLOAT_803db414 + *pfVar10;
            pfVar10[2] = *(float *)(iVar11 + 0x1424) * FLOAT_803db414 + pfVar10[2];
            fVar1 = *pfVar10;
            if (*(float *)(iVar11 + 0x1378) <= fVar1) {
              if (*(float *)(iVar11 + 0x1390) < fVar1) {
                *pfVar10 = -(FLOAT_803df1c8 * *(float *)(iVar11 + 0x1390) - fVar1);
              }
            }
            else {
              *pfVar10 = FLOAT_803df1c8 * *(float *)(iVar11 + 0x1390) + fVar1;
            }
            fVar1 = pfVar10[2];
            if (*(float *)(iVar11 + 0x1380) <= fVar1) {
              if (*(float *)(iVar11 + 0x13b0) < fVar1) {
                pfVar10[2] = -(FLOAT_803df1c8 * *(float *)(iVar11 + 0x13b0) - fVar1);
              }
            }
            else {
              pfVar10[2] = FLOAT_803df1c8 * *(float *)(iVar11 + 0x13b0) + fVar1;
            }
          }
          local_164 = pfVar10[1] - *(float *)(iVar11 + (uint)*(ushort *)(pfVar10 + 4) * 4 + 8);
          iVar7 = (uint)*(ushort *)((int)pfVar10 + 0x12) * 0x2c;
          fVar1 = pfVar10[3];
          local_158 = *pfVar10;
          local_160 = *(float *)(iVar11 + iVar7 + 0x1008) * fVar1 + local_158;
          local_16c = *(float *)(iVar11 + iVar7 + 0x1014) * fVar1 + local_164;
          local_170 = pfVar10[2];
          local_178 = *(float *)(iVar11 + iVar7 + 0x1020) * fVar1 + local_170;
          local_15c = *(float *)(iVar11 + iVar7 + 0x100c) * fVar1 + local_158;
          local_168 = *(float *)(iVar11 + iVar7 + 0x1018) * fVar1 + local_164;
          local_174 = *(float *)(iVar11 + iVar7 + 0x1024) * fVar1 + local_170;
          local_158 = *(float *)(iVar11 + iVar7 + 0x1010) * fVar1 + local_158;
          local_164 = *(float *)(iVar11 + iVar7 + 0x101c) * fVar1 + local_164;
          local_170 = *(float *)(iVar11 + iVar7 + 0x1028) * fVar1 + local_170;
          write_volatile_4(0xcc008000,local_160);
          write_volatile_4(0xcc008000,local_16c);
          write_volatile_4(0xcc008000,local_178);
          write_volatile_2(0xcc008000,local_184._0_2_);
          write_volatile_2(0xcc008000,local_184._2_2_);
          write_volatile_4(0xcc008000,local_15c);
          write_volatile_4(0xcc008000,local_168);
          write_volatile_4(0xcc008000,local_174);
          write_volatile_2(0xcc008000,local_180._0_2_);
          write_volatile_2(0xcc008000,local_180._2_2_);
          write_volatile_4(0xcc008000,local_158);
          write_volatile_4(0xcc008000,local_164);
          write_volatile_4(0xcc008000,local_170);
          write_volatile_2(0xcc008000,local_17c._0_2_);
          write_volatile_2(0xcc008000,local_17c._2_2_);
          pfVar10 = pfVar10 + 6;
        }
      }
      else {
        FUN_801378a8(s_____Error_non_existant_cloud_id___8030f630,iVar9);
      }
    }
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  FUN_80286124(0);
  return;
}

