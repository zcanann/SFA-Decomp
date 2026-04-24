// Function: FUN_801a39d0
// Entry: 801a39d0
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x801a3e10) */
/* WARNING: Removing unreachable block (ram,0x801a3e00) */
/* WARNING: Removing unreachable block (ram,0x801a3df0) */
/* WARNING: Removing unreachable block (ram,0x801a3de0) */
/* WARNING: Removing unreachable block (ram,0x801a3de8) */
/* WARNING: Removing unreachable block (ram,0x801a3df8) */
/* WARNING: Removing unreachable block (ram,0x801a3e08) */
/* WARNING: Removing unreachable block (ram,0x801a3e18) */

void FUN_801a39d0(void)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f24;
  double dVar12;
  undefined8 in_f25;
  double dVar13;
  undefined8 in_f26;
  double dVar14;
  undefined8 in_f27;
  double dVar15;
  undefined8 in_f28;
  double dVar16;
  undefined8 in_f29;
  double dVar17;
  undefined8 in_f30;
  double dVar18;
  undefined8 in_f31;
  double dVar19;
  float local_138;
  float local_134;
  float local_130;
  undefined auStack300 [12];
  float local_120;
  float local_11c;
  float local_118;
  undefined auStack276 [52];
  double local_e0;
  double local_d8;
  undefined4 local_d0;
  uint uStack204;
  double local_c8;
  double local_c0;
  undefined4 local_b8;
  uint uStack180;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  iVar4 = FUN_802860cc();
  fVar2 = FLOAT_803e4390;
  iVar7 = *(int *)(iVar4 + 0x4c);
  pbVar6 = *(byte **)(iVar4 + 0xb8);
  *(float *)(iVar4 + 0x2c) = FLOAT_803e4390;
  *(float *)(iVar4 + 0x28) = fVar2;
  *(float *)(iVar4 + 0x24) = fVar2;
  iVar5 = FUN_8001ffb4((int)*(short *)(iVar7 + 0x1e));
  if (iVar5 != 0) {
    if ((char)*pbVar6 < '\0') {
      uVar3 = FUN_8001ffb4((int)*(short *)(iVar7 + 0x20));
      *pbVar6 = (byte)((uVar3 & 0xff) << 7) | *pbVar6 & 0x7f;
    }
    else {
      iVar5 = (int)*(char *)(iVar7 + 0x19) % 3;
      uVar3 = countLeadingZeros(((uint)(byte)((*(float *)(pbVar6 + 4) == FLOAT_803e4390) << 1) <<
                                0x1c) >> 0x1d ^ 1);
      fVar2 = FLOAT_803e4394;
      if (uVar3 >> 5 == 0) {
        fVar2 = FLOAT_803e4398 * *(float *)(pbVar6 + 4);
      }
      dVar14 = (double)fVar2;
      FUN_8002b47c(iVar4,auStack276,0);
      dVar15 = DOUBLE_803e43b0;
      local_e0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 4) ^ 0x80000000);
      iVar8 = (int)(FLOAT_803e439c * FLOAT_803db414 + (float)(local_e0 - DOUBLE_803e43b0));
      local_d8 = (double)(longlong)iVar8;
      *(short *)(iVar4 + 4) = (short)iVar8;
      puVar9 = &DAT_80322ed8 + iVar5 * 6;
      dVar16 = (double)FLOAT_803e43a4;
      dVar17 = (double)FLOAT_803e43a8;
      dVar18 = (double)FLOAT_803e43ac;
      dVar19 = (double)FLOAT_803e43a0;
      dVar13 = (double)FLOAT_803e4390;
      for (iVar8 = -0x7fff; iVar8 < 0x7fff; iVar8 = iVar8 + (&DAT_80322ee0)[iVar5 * 6]) {
        uVar3 = FUN_800221a0(-DAT_803dbe94);
        local_d8 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        dVar12 = (double)(float)(local_d8 - dVar15);
        iVar1 = (int)(dVar17 * (double)(float)(&DAT_80322eec)[iVar5 * 6]);
        local_e0 = (double)(longlong)iVar1;
        uStack204 = iVar8 + iVar1 ^ 0x80000000;
        local_d0 = 0x43300000;
        dVar11 = (double)FUN_80294204((double)(float)((double)(float)(dVar16 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack204) - dVar15)) /
                                                  dVar18));
        local_138 = (float)((double)(float)(dVar19 * (double)(float)(dVar14 * (double)FLOAT_803dbe90
                                                                    )) * dVar11 + dVar12);
        uVar3 = FUN_800221a0(-DAT_803dbe94);
        local_c8 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        dVar12 = (double)(float)(local_c8 - dVar15);
        iVar1 = (int)(dVar17 * (double)(float)(&DAT_80322eec)[iVar5 * 6]);
        local_c0 = (double)(longlong)iVar1;
        uStack180 = iVar8 + iVar1 ^ 0x80000000;
        local_b8 = 0x43300000;
        dVar11 = (double)FUN_80293e80((double)(float)((double)(float)(dVar16 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack180) - dVar15)) /
                                                  dVar18));
        local_134 = (float)((double)(float)(dVar19 * (double)(float)(dVar14 * (double)FLOAT_803dbe90
                                                                    )) * dVar11 + dVar12);
        local_130 = (float)dVar13;
        FUN_80247574(auStack276,&local_138,&local_138);
        local_120 = local_138 + *(float *)(iVar4 + 0xc);
        local_11c = local_134 + *(float *)(iVar4 + 0x10);
        local_118 = local_130 + *(float *)(iVar4 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))(iVar4,*puVar9,auStack300,0x200001,0xffffffff,iVar4 + 0x24);
        (**(code **)(*DAT_803dca88 + 8))(iVar4,*puVar9,auStack300,0x200001,0xffffffff,iVar4 + 0x24);
        (**(code **)(*DAT_803dca88 + 8))(iVar4,*puVar9,auStack300,0x200001,0xffffffff,iVar4 + 0x24);
      }
      iVar5 = FUN_80080150(pbVar6 + 4);
      if (iVar5 == 0) {
        iVar5 = FUN_8001ffb4((int)*(short *)(iVar7 + 0x20));
        if (iVar5 != 0) {
          FUN_80080178(pbVar6 + 4,0x3c);
          FUN_8000bb18(iVar4,0x366);
          if (*(int *)(*(int *)(iVar4 + 0x4c) + 0x14) != 0x47f5e) {
            FUN_8000bb18(iVar4,0x409);
          }
        }
      }
      else {
        uStack180 = DAT_803dbe98 ^ 0x80000000;
        local_b8 = 0x43300000;
        local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar4 + 2) ^ 0x80000000);
        iVar5 = (int)((float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e43b0) *
                      FLOAT_803db414 + (float)(local_c0 - DOUBLE_803e43b0));
        local_c8 = (double)(longlong)iVar5;
        *(short *)(iVar4 + 2) = (short)iVar5;
        iVar5 = FUN_800801a8(pbVar6 + 4);
        if (iVar5 != 0) {
          *pbVar6 = *pbVar6 & 0x7f | 0x80;
          *(undefined2 *)(iVar4 + 2) = 0;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  __psq_l0(auStack88,uVar10);
  __psq_l1(auStack88,uVar10);
  __psq_l0(auStack104,uVar10);
  __psq_l1(auStack104,uVar10);
  __psq_l0(auStack120,uVar10);
  __psq_l1(auStack120,uVar10);
  FUN_80286118();
  return;
}

