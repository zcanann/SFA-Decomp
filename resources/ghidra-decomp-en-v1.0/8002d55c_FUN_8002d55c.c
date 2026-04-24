// Function: FUN_8002d55c
// Entry: 8002d55c
// Size: 2612 bytes

/* WARNING: Removing unreachable block (ram,0x8002df70) */

void FUN_8002d55c(undefined4 param_1,undefined4 param_2,undefined param_3,undefined2 param_4,
                 undefined4 param_5)

{
  byte bVar1;
  short sVar2;
  ushort uVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar9;
  code *pcVar10;
  int *piVar11;
  int iVar12;
  int iVar13;
  int iVar14;
  undefined4 *puVar15;
  int iVar16;
  undefined4 uVar17;
  undefined8 in_f31;
  double dVar18;
  ulonglong uVar19;
  int local_208;
  undefined4 local_204 [20];
  int local_1b4 [20];
  undefined auStack356 [6];
  ushort local_15e;
  undefined4 local_15c;
  undefined4 local_158;
  undefined4 local_154;
  undefined4 local_150;
  undefined local_12e;
  float local_128;
  float local_124;
  undefined2 local_120;
  short local_11e;
  undefined2 local_11c;
  short *local_118;
  int local_114;
  int *local_fc;
  undefined2 local_c2;
  undefined local_b8;
  ushort local_b4;
  undefined2 local_b2;
  undefined2 local_b0;
  undefined4 local_88;
  undefined local_73;
  char local_72;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined auStack8 [8];
  
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar19 = FUN_802860c0();
  psVar5 = (short *)(uVar19 >> 0x20);
  sVar2 = *psVar5;
  iVar13 = (int)sVar2;
  if ((uVar19 & 2) == 0) {
    if (DAT_803dcb9c < iVar13) {
      iVar13 = 0;
      goto LAB_8002df70;
    }
    iVar13 = (int)*(short *)(DAT_803dcba0 + iVar13 * 2);
  }
  FUN_800033a8(auStack356,0,0x10c);
  iVar6 = FUN_8002c450(iVar13);
  local_114 = iVar6;
  if ((iVar6 == 0) || (iVar6 == -1)) {
    FUN_801378a8(s_Warning__Unknown_object_type___d_802cad04,iVar13,(int)*psVar5,(int)local_11e);
    iVar13 = 0;
  }
  else {
    local_120 = *(undefined2 *)(iVar6 + 0x52);
    local_15c = *(undefined4 *)(iVar6 + 4);
    local_15e = 2;
    if ((*(uint *)(iVar6 + 0x44) & 0x80) != 0) {
      local_15e = 0x82;
    }
    if ((*(uint *)(iVar6 + 0x44) & 0x40000) != 0) {
      local_b4 = local_b4 | 0x80;
    }
    if ((uVar19 & 4) != 0) {
      local_15e = local_15e | 0x2000;
    }
    local_158 = *(undefined4 *)(psVar5 + 4);
    local_154 = *(undefined4 *)(psVar5 + 6);
    local_150 = *(undefined4 *)(psVar5 + 8);
    local_11c = (undefined2)iVar13;
    local_c2 = 0xffff;
    local_b0 = 0xffff;
    local_12e = 0xff;
    local_88 = 0;
    local_73 = 0xff;
    uStack84 = (uint)*(byte *)(psVar5 + 3) << 3 ^ 0x80000000;
    local_58 = 0x43300000;
    local_128 = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803de8b0);
    uStack76 = (uint)*(byte *)((int)psVar5 + 7) << 3 ^ 0x80000000;
    local_50 = 0x43300000;
    local_124 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de8b0);
    iVar13 = (int)(*(byte *)((int)psVar5 + 5) & 0x18) >> 3;
    if (iVar13 == 0) {
      local_72 = *(char *)(iVar6 + 0x8e);
    }
    else {
      local_72 = (char)iVar13 + -1;
    }
    local_fc = (int *)0x0;
    local_11e = sVar2;
    local_118 = psVar5;
    local_b8 = param_3;
    local_b2 = param_4;
    if ((int)*(short *)(iVar6 + 0x50) != 0xffffffff) {
      local_fc = (int *)FUN_80013ec8((int)*(short *)(iVar6 + 0x50) & 0xffff,6);
    }
    if ((local_11e == 0x1f) || ((local_11e < 0x1f && (local_11e == 0)))) {
      uVar7 = 0x1cb;
    }
    else if (((local_fc == (int *)0x0) ||
             (pcVar10 = *(code **)(*local_fc + 0x18), pcVar10 == (code *)0xffffffff)) ||
            (pcVar10 == (code *)0x0)) {
      uVar7 = 0;
    }
    else {
      uVar7 = (*pcVar10)(auStack356);
    }
    if ((*(uint *)(iVar6 + 0x44) & 0x20) == 0) {
      uVar7 = uVar7 | 1;
    }
    else {
      uVar7 = uVar7 & 0xfffffffe;
    }
    if (*(short *)(iVar6 + 0x48) == 0) {
      uVar7 = uVar7 & 0xfffffffd;
    }
    else {
      uVar7 = uVar7 | 2;
    }
    if (*(short *)(iVar6 + 0x48) == 3) {
      uVar7 = uVar7 | 0x8000;
    }
    if ((*(uint *)(iVar6 + 0x44) & 1) != 0) {
      uVar7 = uVar7 | 0x200;
    }
    iVar12 = 0;
    iVar13 = 0;
    iVar16 = (int)*(char *)(iVar6 + 0x55);
    if ((uVar7 & 0x400) == 0) {
      if ((uVar7 & 0x200) == 0) {
        iVar9 = 0;
        puVar15 = local_204;
        piVar11 = local_1b4;
        for (; iVar13 < iVar16; iVar13 = iVar13 + 1) {
          uVar8 = FUN_80029570(-*(int *)(*(int *)(iVar6 + 8) + iVar9),uVar7,&local_208);
          *puVar15 = uVar8;
          *piVar11 = iVar12;
          iVar12 = iVar12 + local_208;
          iVar9 = iVar9 + 4;
          puVar15 = puVar15 + 1;
          piVar11 = piVar11 + 1;
        }
      }
    }
    else {
      uVar4 = uVar7 >> 0xb & 0xf;
      if ((int)uVar4 < iVar16) {
        uVar8 = FUN_80029570(-*(int *)(*(int *)(iVar6 + 8) + uVar4 * 4),uVar7,&local_208);
        local_204[uVar4] = uVar8;
        local_1b4[uVar4] = 0;
        iVar12 = local_208;
      }
    }
    iVar9 = FUN_8002d118(auStack356,iVar6,psVar5,uVar7);
    iVar13 = FUN_80023cc8(iVar9 + iVar12,0xe,0);
    FUN_80003494(iVar13,auStack356,0x10c);
    FUN_800033a8(iVar13 + 0x10c,0,iVar9 + iVar12 + -0x10c);
    *(int *)(iVar13 + 0x7c) = iVar13 + 0x10c;
    *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) = *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) | 0x800000
    ;
    iVar12 = 0;
    *(undefined4 *)(iVar13 + 0x108) = 0;
    if ((uVar7 & 0x400) == 0) {
      if ((uVar7 & 0x200) == 0) {
        piVar11 = local_1b4;
        iVar14 = 0;
        puVar15 = local_204;
        for (; iVar12 < iVar16; iVar12 = iVar12 + 1) {
          *(int *)(*(int *)(iVar13 + 0x7c) + iVar14) = iVar13 + iVar9 + *piVar11;
          FUN_800294e4(*puVar15,uVar7,*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14));
          uVar3 = *(ushort *)(**(int **)(*(int *)(iVar13 + 0x7c) + iVar14) + 2);
          if (((uVar3 & 0x8000) == 0) && ((uVar3 & 0x4000) == 0)) {
            *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) =
                 *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) & 0xff7fffff;
          }
          FUN_800285c8(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14),iVar13);
          FUN_8002cec0((double)*(float *)(iVar13 + 8),
                       *(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14));
          if ((*(uint *)(*(int *)(iVar13 + 0x50) + 0x44) & 0x800) == 0) {
            bVar1 = *(byte *)(*(int *)(iVar13 + 0x50) + 0x5f);
            if ((bVar1 & 1) == 0) {
              if ((bVar1 & 0x80) != 0) {
                FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14),FUN_80074518);
              }
            }
            else {
              FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14),FUN_80073d04);
            }
          }
          else {
            FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar14),FUN_80074d04);
          }
          piVar11 = piVar11 + 1;
          iVar14 = iVar14 + 4;
          puVar15 = puVar15 + 1;
        }
      }
    }
    else {
      uVar4 = uVar7 >> 0xb & 0xf;
      if ((int)uVar4 < iVar16) {
        iVar12 = uVar4 * 4;
        *(int *)(*(int *)(iVar13 + 0x7c) + iVar12) = iVar13 + iVar9 + local_1b4[uVar4];
        FUN_800294e4(local_204[uVar4],uVar7,*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12));
        if ((*(ushort *)(**(int **)(*(int *)(iVar13 + 0x7c) + iVar12) + 2) & 0x8000) == 0) {
          *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) =
               *(uint *)(*(int *)(iVar13 + 0x50) + 0x44) & 0xff7fffff;
        }
        FUN_800285c8(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12),iVar13);
        FUN_8002cec0((double)*(float *)(iVar13 + 8),
                     *(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12));
        if ((*(uint *)(*(int *)(iVar13 + 0x50) + 0x44) & 0x800) == 0) {
          bVar1 = *(byte *)(*(int *)(iVar13 + 0x50) + 0x5f);
          if ((bVar1 & 1) == 0) {
            if ((bVar1 & 0x80) != 0) {
              FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12),FUN_80074518);
            }
          }
          else {
            FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12),FUN_80073d04);
          }
        }
        else {
          FUN_8002853c(*(undefined4 *)(*(int *)(iVar13 + 0x7c) + iVar12),FUN_80074d04);
        }
      }
    }
    iVar12 = FUN_80022e24(*(int *)(iVar13 + 0x7c) + *(char *)(iVar6 + 0x55) * 4);
    sVar2 = *(short *)(iVar13 + 0x46);
    if ((sVar2 == 0x1f) || ((sVar2 < 0x1f && (sVar2 == 0)))) {
      iVar16 = 0x8e0;
    }
    else if ((*(int **)(iVar13 + 0x68) == (int *)0x0) ||
            (pcVar10 = *(code **)(**(int **)(iVar13 + 0x68) + 0x1c), pcVar10 == (code *)0x0)) {
      iVar16 = 0;
    }
    else {
      iVar16 = (*pcVar10)(iVar13,iVar12);
    }
    if (iVar16 == 0) {
      *(undefined4 *)(iVar13 + 0xb8) = 0;
    }
    else {
      *(int *)(iVar13 + 0xb8) = iVar12;
      iVar12 = iVar12 + iVar16;
    }
    if (((uVar7 & 0x40) != 0) || ((*(uint *)(*(int *)(iVar13 + 0x50) + 0x44) & 0x400000) != 0)) {
      sVar2 = *(short *)(iVar13 + 0x46);
      iVar12 = FUN_80022e24(iVar12);
      *(int *)(iVar13 + 0x60) = iVar12;
      iVar12 = FUN_80022e3c(iVar12 + 8);
      *(int *)(*(int *)(iVar13 + 0x60) + 4) = iVar12;
      FUN_8002c6c8(iVar13,(int)sVar2,*(undefined4 *)(iVar13 + 0x60),0,1);
      iVar12 = iVar12 + 0x50;
    }
    if (((uVar7 & 0x100) != 0) && (**(int **)(iVar13 + 0x7c) != 0)) {
      iVar12 = FUN_80022e24(iVar12);
      *(int *)(iVar13 + 0x5c) = iVar12;
      iVar12 = FUN_80022e3c(iVar12 + 8);
      *(int *)(*(int *)(iVar13 + 0x5c) + 4) = iVar12;
      iVar12 = iVar12 + 0x800;
    }
    if (((uVar7 & 2) != 0) && (*(short *)(iVar6 + 0x48) != 0)) {
      iVar12 = FUN_800628e4(iVar13,iVar12,0);
    }
    dVar18 = (double)FLOAT_803de8cc;
    iVar16 = 0;
    for (iVar9 = 0; iVar9 < *(char *)(*(int *)(iVar13 + 0x50) + 0x55); iVar9 = iVar9 + 1) {
      puVar15 = *(undefined4 **)(*(int *)(iVar13 + 0x7c) + iVar16);
      if (puVar15 != (undefined4 *)0x0) {
        uStack76 = FUN_80028434(*puVar15);
        uStack76 = uStack76 & 0xffff;
        local_50 = 0x43300000;
        if (dVar18 < (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de8a8)) {
          uStack76 = FUN_80028434(*puVar15);
          uStack76 = uStack76 & 0xffff;
          local_50 = 0x43300000;
          dVar18 = (double)(float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803de8a8);
        }
      }
      iVar16 = iVar16 + 4;
    }
    uVar7 = (uint)*(byte *)(*(int *)(iVar13 + 0x50) + 0x73);
    if (uVar7 != 0) {
      local_50 = 0x43300000;
      dVar18 = (double)(float)(dVar18 * (double)((FLOAT_803de8cc *
                                                 (float)((double)CONCAT44(0x43300000,uVar7) -
                                                        DOUBLE_803de8a8)) / FLOAT_803de8d0));
      uStack76 = uVar7;
    }
    *(float *)(iVar13 + 0xa8) = (float)dVar18;
    if ((*(char *)(iVar6 + 0x61) != '\0') &&
       (iVar12 = FUN_80035fcc(iVar13,iVar12), (*(byte *)(iVar6 + 0x65) & 8) != 0)) {
      iVar12 = FUN_800356f0(iVar13,iVar12);
    }
    if (*(char *)(iVar6 + 0x5a) != '\0') {
      iVar12 = FUN_80022e24(iVar12);
      *(int *)(iVar13 + 0x6c) = iVar12;
      iVar12 = iVar12 + (uint)*(byte *)(iVar6 + 0x5a) * 0x12;
    }
    if (*(char *)(iVar6 + 0x59) != '\0') {
      iVar12 = FUN_80022e24(iVar12);
      *(int *)(iVar13 + 0x70) = iVar12;
      iVar12 = iVar12 + (uint)*(byte *)(iVar6 + 0x59) * 0x10;
    }
    if (*(char *)(iVar6 + 0x72) != '\0') {
      iVar12 = FUN_80022e24(iVar12);
      *(int *)(iVar13 + 0x74) = iVar12;
      iVar12 = iVar12 + (uint)*(byte *)(iVar6 + 0x72) * 0x18;
    }
    if ((*(char *)(iVar6 + 0x61) != '\0') && (*(char *)(iVar6 + 0x66) != '\0')) {
      uVar8 = FUN_80022e24(iVar12);
      iVar12 = FUN_80035828((int)*(short *)(iVar13 + 0x46),**(undefined4 **)(iVar13 + 0x7c),
                            *(undefined4 *)(iVar13 + 0x54),uVar8,iVar13);
    }
    if (*(char *)(iVar6 + 0x72) != '\0') {
      uVar8 = FUN_80022e24(iVar12);
      *(undefined4 *)(iVar13 + 0x78) = uVar8;
      iVar12 = 0;
      iVar16 = 0;
      for (iVar9 = 0; iVar9 < (int)(uint)*(byte *)(iVar6 + 0x72); iVar9 = iVar9 + 1) {
        *(undefined *)(*(int *)(iVar13 + 0x78) + iVar16 + 4) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar12 + 0x10);
        *(undefined *)(*(int *)(iVar13 + 0x78) + iVar16) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar12 + 0xc);
        *(undefined *)(*(int *)(iVar13 + 0x78) + iVar16 + 3) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar12 + 0xf);
        *(undefined *)(*(int *)(iVar13 + 0x78) + iVar16 + 1) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar12 + 0xd);
        *(undefined *)(*(int *)(iVar13 + 0x78) + iVar16 + 2) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar12 + 0xe);
        iVar12 = iVar12 + 0x18;
        iVar16 = iVar16 + 5;
      }
    }
    *(undefined4 *)(iVar13 + 0x30) = param_5;
  }
LAB_8002df70:
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  FUN_8028610c(iVar13);
  return;
}

