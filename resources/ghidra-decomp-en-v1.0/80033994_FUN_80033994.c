// Function: FUN_80033994
// Entry: 80033994
// Size: 1520 bytes

/* WARNING: Removing unreachable block (ram,0x80033f5c) */
/* WARNING: Removing unreachable block (ram,0x80033f54) */
/* WARNING: Removing unreachable block (ram,0x80033f64) */

void FUN_80033994(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  float fVar1;
  short *psVar2;
  uint uVar3;
  short *psVar4;
  short **ppsVar5;
  short **ppsVar6;
  undefined4 uVar7;
  double dVar8;
  double extraout_f1;
  double dVar9;
  undefined8 in_f29;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  uVar11 = FUN_802860dc();
  psVar2 = (short *)((ulonglong)uVar11 >> 0x20);
  psVar4 = (short *)uVar11;
  dVar9 = extraout_f1;
  FUN_80037d74();
  ppsVar6 = *(short ***)(psVar2 + 0x2a);
  ppsVar5 = *(short ***)(psVar4 + 0x2a);
  *(ushort *)(ppsVar6 + 0x18) = *(ushort *)(ppsVar6 + 0x18) | 8;
  *(ushort *)(ppsVar5 + 0x18) = *(ushort *)(ppsVar5 + 0x18) | 8;
  *ppsVar6 = psVar4;
  *ppsVar5 = psVar2;
  if (*(int *)(psVar2 + 0x18) == 0) {
    local_84 = (float)dVar9;
    local_88 = (float)param_2;
    local_8c = (float)param_3;
  }
  else {
    FUN_8000dfa8(dVar9,param_2,param_3,&local_84,&local_88,&local_8c);
  }
  if (*(int *)(psVar4 + 0x18) == 0) {
    local_90 = (float)dVar9;
    local_94 = (float)param_2;
    local_98 = (float)param_3;
  }
  else {
    FUN_8000dfa8(dVar9,param_2,param_3,&local_90,&local_94,&local_98);
  }
  if (((psVar2[0x22] == 1) && (*(char *)((int)ppsVar6 + 0x6a) != '\0')) &&
     ((*(ushort *)(ppsVar5 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84;
    *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
    *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
    if (param_6 == 0) {
      FUN_8000e0a0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                   (double)*(float *)(psVar2 + 10),psVar2 + 0xc,psVar2 + 0xe,psVar2 + 0x10,
                   *(undefined4 *)(psVar2 + 0x18));
    }
    else {
      *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar9);
      *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
      *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
    }
  }
  else if (((psVar4[0x22] == 1) && (*(char *)((int)ppsVar5 + 0x6a) != '\0')) &&
          ((*(ushort *)(ppsVar6 + 0x18) & 0x400) == 0)) {
    *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
    *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
    *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
    if (param_6 == 0) {
      FUN_8000e0a0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                   (double)*(float *)(psVar4 + 10),psVar4 + 0xc,psVar4 + 0xe,psVar4 + 0x10,
                   *(undefined4 *)(psVar4 + 0x18));
    }
    else {
      *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar9);
      *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
      *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
    }
  }
  else if (*(char *)((int)ppsVar5 + 0x6a) == '\0') {
    if (*(char *)((int)ppsVar6 + 0x6a) != '\0') {
      *(float *)(psVar2 + 6) = *(float *)(psVar2 + 6) - local_84;
      *(float *)(psVar2 + 8) = *(float *)(psVar2 + 8) - local_88;
      *(float *)(psVar2 + 10) = *(float *)(psVar2 + 10) - local_8c;
      if (param_6 == 0) {
        FUN_8000e0a0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                     (double)*(float *)(psVar2 + 10),psVar2 + 0xc,psVar2 + 0xe,psVar2 + 0x10,
                     *(undefined4 *)(psVar2 + 0x18));
      }
      else {
        *(float *)(psVar2 + 0xc) = (float)((double)*(float *)(psVar2 + 0xc) - dVar9);
        *(float *)(psVar2 + 0xe) = (float)((double)*(float *)(psVar2 + 0xe) - param_2);
        *(float *)(psVar2 + 0x10) = (float)((double)*(float *)(psVar2 + 0x10) - param_3);
      }
    }
  }
  else if (*(char *)((int)ppsVar6 + 0x6a) == '\0') {
    if (*(char *)((int)ppsVar5 + 0x6a) != '\0') {
      *(float *)(psVar4 + 6) = *(float *)(psVar4 + 6) + local_90;
      *(float *)(psVar4 + 8) = *(float *)(psVar4 + 8) + local_94;
      *(float *)(psVar4 + 10) = *(float *)(psVar4 + 10) + local_98;
      if (param_6 == 0) {
        FUN_8000e0a0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                     (double)*(float *)(psVar4 + 10),psVar4 + 0xc,psVar4 + 0xe,psVar4 + 0x10,
                     *(undefined4 *)(psVar4 + 0x18));
      }
      else {
        *(float *)(psVar4 + 0xc) = (float)((double)*(float *)(psVar4 + 0xc) + dVar9);
        *(float *)(psVar4 + 0xe) = (float)((double)*(float *)(psVar4 + 0xe) + param_2);
        *(float *)(psVar4 + 0x10) = (float)((double)*(float *)(psVar4 + 0x10) + param_3);
      }
    }
  }
  else {
    uVar3 = FUN_800217c0(-dVar9,-param_3);
    uStack124 = (int)*psVar2 - (uVar3 & 0xffff);
    if (0x8000 < (int)uStack124) {
      uStack124 = uStack124 - 0xffff;
    }
    if ((int)uStack124 < -0x8000) {
      uStack124 = uStack124 + 0xffff;
    }
    uStack100 = (int)*psVar4 - ((uVar3 & 0xffff) + 0x8000 & 0xffff);
    if (0x8000 < (int)uStack100) {
      uStack100 = uStack100 - 0xffff;
    }
    if ((int)uStack100 < -0x8000) {
      uStack100 = uStack100 + 0xffff;
    }
    uStack124 = uStack124 ^ 0x80000000;
    local_80 = 0x43300000;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803de948 *
                                          (float)((double)CONCAT44(0x43300000,uStack124) -
                                                 DOUBLE_803de940)) / FLOAT_803de94c));
    uStack116 = (uint)*(byte *)((int)ppsVar6 + 0x6a);
    local_78 = 0x43300000;
    uStack108 = (uint)*(byte *)((int)ppsVar6 + 0x6b);
    local_70 = 0x43300000;
    dVar10 = (double)((float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803de950) *
                      (float)(dVar9 * dVar9) +
                     (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803de950) *
                     (FLOAT_803de918 - (float)(dVar9 * dVar9)));
    uStack100 = uStack100 ^ 0x80000000;
    local_68 = 0x43300000;
    dVar9 = (double)FUN_80294204((double)((FLOAT_803de948 *
                                          (float)((double)CONCAT44(0x43300000,uStack100) -
                                                 DOUBLE_803de940)) / FLOAT_803de94c));
    uStack92 = (uint)*(byte *)((int)ppsVar5 + 0x6a);
    local_60 = 0x43300000;
    uStack84 = (uint)*(byte *)((int)ppsVar5 + 0x6b);
    local_58 = 0x43300000;
    dVar9 = (double)((float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803de950) *
                     (float)(dVar9 * dVar9) +
                    (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803de950) *
                    (FLOAT_803de918 - (float)(dVar9 * dVar9)));
    if ((double)(float)(dVar9 * (double)FLOAT_803db450) <= dVar10) {
      if (dVar9 < (double)(float)(dVar10 * (double)FLOAT_803db450)) {
        dVar9 = (double)FLOAT_803de910;
      }
    }
    else {
      dVar10 = (double)FLOAT_803de910;
    }
    dVar8 = (double)FLOAT_803de910;
    if (dVar8 < (double)(float)(dVar10 + dVar9)) {
      dVar8 = (double)(float)(dVar9 / (double)(float)(dVar10 + dVar9));
    }
    *(float *)(psVar2 + 6) = -(float)((double)local_84 * dVar8 - (double)*(float *)(psVar2 + 6));
    *(float *)(psVar2 + 8) = -(float)((double)local_88 * dVar8 - (double)*(float *)(psVar2 + 8));
    *(float *)(psVar2 + 10) = -(float)((double)local_8c * dVar8 - (double)*(float *)(psVar2 + 10));
    FUN_8000e0a0((double)*(float *)(psVar2 + 6),(double)*(float *)(psVar2 + 8),
                 (double)*(float *)(psVar2 + 10),psVar2 + 0xc,psVar2 + 0xe,psVar2 + 0x10,
                 *(undefined4 *)(psVar2 + 0x18));
    fVar1 = (float)((double)FLOAT_803de918 - dVar8);
    *(float *)(psVar4 + 6) = local_90 * fVar1 + *(float *)(psVar4 + 6);
    *(float *)(psVar4 + 8) = local_94 * fVar1 + *(float *)(psVar4 + 8);
    *(float *)(psVar4 + 10) = local_98 * fVar1 + *(float *)(psVar4 + 10);
    FUN_8000e0a0((double)*(float *)(psVar4 + 6),(double)*(float *)(psVar4 + 8),
                 (double)*(float *)(psVar4 + 10),psVar4 + 0xc,psVar4 + 0xe,psVar4 + 0x10,
                 *(undefined4 *)(psVar4 + 0x18));
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286128();
  return;
}

