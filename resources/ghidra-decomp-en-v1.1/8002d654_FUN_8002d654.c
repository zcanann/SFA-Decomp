// Function: FUN_8002d654
// Entry: 8002d654
// Size: 2612 bytes

/* WARNING: Removing unreachable block (ram,0x8002e068) */
/* WARNING: Removing unreachable block (ram,0x8002d664) */

void FUN_8002d654(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined4 param_12,
                 uint *param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  byte bVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  ushort *puVar10;
  ushort uVar11;
  uint *puVar12;
  code *pcVar13;
  int iVar14;
  int iVar15;
  undefined4 *puVar16;
  int iVar17;
  int *piVar18;
  int iVar19;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  double extraout_f1_01;
  double extraout_f1_02;
  double extraout_f1_03;
  undefined8 uVar20;
  undefined8 extraout_f1_04;
  double in_f31;
  double dVar21;
  double in_ps31_1;
  ulonglong uVar22;
  int local_208;
  undefined4 local_204 [20];
  int local_1b4 [20];
  undefined auStack_164 [6];
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
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar22 = FUN_80286824();
  psVar5 = (short *)(uVar22 >> 0x20);
  sVar2 = *psVar5;
  iVar15 = (int)sVar2;
  if ((uVar22 & 2) == 0) {
    if (DAT_803dd81c < iVar15) goto LAB_8002e068;
    iVar15 = (int)*(short *)(DAT_803dd820 + iVar15 * 2);
  }
  uVar8 = param_12;
  puVar12 = param_13;
  uVar20 = extraout_f1;
  FUN_800033a8((int)auStack_164,0,0x10c);
  iVar6 = FUN_8002c528(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  local_114 = iVar6;
  if ((iVar6 == 0) || (iVar6 == -1)) {
    FUN_80137c30(extraout_f1_00,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_Warning__Unknown_object_type___d_802cb8d8,iVar15,(int)*psVar5,(int)local_11e,
                 puVar12,param_14,param_15,param_16);
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
    if ((uVar22 & 4) != 0) {
      local_15e = local_15e | 0x2000;
    }
    local_158 = *(undefined4 *)(psVar5 + 4);
    local_154 = *(undefined4 *)(psVar5 + 6);
    local_150 = *(undefined4 *)(psVar5 + 8);
    local_11c = (undefined2)iVar15;
    local_b2 = (undefined2)param_12;
    local_c2 = 0xffff;
    local_b0 = 0xffff;
    local_12e = 0xff;
    local_88 = 0;
    local_73 = 0xff;
    uStack_54 = (uint)*(byte *)(psVar5 + 3) << 3 ^ 0x80000000;
    local_58 = 0x43300000;
    local_128 = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df530);
    uStack_4c = (uint)*(byte *)((int)psVar5 + 7) << 3 ^ 0x80000000;
    local_50 = 0x43300000;
    local_124 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df530);
    iVar15 = (int)(*(byte *)((int)psVar5 + 5) & 0x18) >> 3;
    if (iVar15 == 0) {
      local_72 = *(char *)(iVar6 + 0x8e);
    }
    else {
      local_72 = (char)iVar15 + -1;
    }
    local_fc = (int *)0x0;
    dVar21 = DOUBLE_803df530;
    local_11e = sVar2;
    local_118 = psVar5;
    local_b8 = param_11;
    if (*(ushort *)(iVar6 + 0x50) != 0xffff) {
      local_fc = (int *)FUN_80013ee8((uint)*(ushort *)(iVar6 + 0x50));
      dVar21 = extraout_f1_01;
    }
    if ((local_11e == 0x1f) || ((local_11e < 0x1f && (local_11e == 0)))) {
      uVar7 = 0x1cb;
    }
    else if (((local_fc == (int *)0x0) ||
             (pcVar13 = *(code **)(*local_fc + 0x18), pcVar13 == (code *)0xffffffff)) ||
            (pcVar13 == (code *)0x0)) {
      uVar7 = 0;
    }
    else {
      uVar7 = (*pcVar13)(auStack_164);
      dVar21 = extraout_f1_02;
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
    iVar15 = 0;
    iVar14 = 0;
    iVar19 = (int)*(char *)(iVar6 + 0x55);
    if ((uVar7 & 0x400) == 0) {
      if ((uVar7 & 0x200) == 0) {
        iVar17 = 0;
        puVar16 = local_204;
        piVar18 = local_1b4;
        for (; iVar14 < iVar19; iVar14 = iVar14 + 1) {
          uVar9 = FUN_80029648(dVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                               -*(int *)(*(int *)(iVar6 + 8) + iVar17),uVar7,&local_208,uVar8,
                               puVar12,param_14,param_15,param_16);
          *puVar16 = uVar9;
          *piVar18 = iVar15;
          iVar15 = iVar15 + local_208;
          iVar17 = iVar17 + 4;
          puVar16 = puVar16 + 1;
          piVar18 = piVar18 + 1;
          dVar21 = extraout_f1_03;
        }
      }
    }
    else {
      uVar3 = uVar7 >> 0xb & 0xf;
      if ((int)uVar3 < iVar19) {
        uVar8 = FUN_80029648(dVar21,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             -*(int *)(*(int *)(iVar6 + 8) + uVar3 * 4),uVar7,&local_208,uVar8,
                             puVar12,param_14,param_15,param_16);
        local_204[uVar3] = uVar8;
        local_1b4[uVar3] = 0;
        iVar15 = local_208;
      }
    }
    uVar3 = uVar7;
    iVar14 = FUN_8002d210((int)auStack_164,iVar6,psVar5,uVar7);
    puVar10 = (ushort *)FUN_80023d8c(iVar14 + iVar15,0xe);
    uVar20 = FUN_80003494((uint)puVar10,(uint)auStack_164,0x10c);
    FUN_800033a8((int)(puVar10 + 0x86),0,(iVar14 + iVar15) - 0x10c);
    *(ushort **)(puVar10 + 0x3e) = puVar10 + 0x86;
    *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) =
         *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) | 0x800000;
    iVar15 = 0;
    puVar10[0x84] = 0;
    puVar10[0x85] = 0;
    if ((uVar7 & 0x400) == 0) {
      if ((uVar7 & 0x200) == 0) {
        piVar18 = local_1b4;
        iVar17 = 0;
        puVar16 = local_204;
        for (; iVar15 < iVar19; iVar15 = iVar15 + 1) {
          *(int *)(*(int *)(puVar10 + 0x3e) + iVar17) = (int)puVar10 + *piVar18 + iVar14;
          FUN_800295bc(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (byte *)*puVar16,uVar7,*(undefined4 *)(*(int *)(puVar10 + 0x3e) + iVar17),
                       uVar3,puVar12,param_14,param_15,param_16);
          uVar11 = *(ushort *)(**(int **)(*(int *)(puVar10 + 0x3e) + iVar17) + 2);
          if (((uVar11 & 0x8000) == 0) && ((uVar11 & 0x4000) == 0)) {
            *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) =
                 *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) & 0xff7fffff;
          }
          FUN_8002868c();
          uVar20 = FUN_8002cfb8();
          if ((*(uint *)(*(int *)(puVar10 + 0x28) + 0x44) & 0x800) == 0) {
            bVar1 = *(byte *)(*(int *)(puVar10 + 0x28) + 0x5f);
            if ((bVar1 & 1) == 0) {
              if ((bVar1 & 0x80) != 0) {
                uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar17),FUN_80074694);
              }
            }
            else {
              uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar17),FUN_80073e80);
            }
          }
          else {
            uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar17),FUN_80074e80);
          }
          piVar18 = piVar18 + 1;
          iVar17 = iVar17 + 4;
          puVar16 = puVar16 + 1;
        }
      }
    }
    else {
      uVar4 = uVar7 >> 0xb & 0xf;
      if ((int)uVar4 < iVar19) {
        iVar15 = uVar4 * 4;
        *(int *)(*(int *)(puVar10 + 0x3e) + iVar15) = (int)puVar10 + iVar14 + local_1b4[uVar4];
        FUN_800295bc(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (byte *)local_204[uVar4],uVar7,
                     *(undefined4 *)(*(int *)(puVar10 + 0x3e) + iVar15),uVar3,puVar12,param_14,
                     param_15,param_16);
        if ((*(ushort *)(**(int **)(*(int *)(puVar10 + 0x3e) + iVar15) + 2) & 0x8000) == 0) {
          *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) =
               *(uint *)(*(int *)(puVar10 + 0x28) + 0x44) & 0xff7fffff;
        }
        FUN_8002868c();
        uVar20 = FUN_8002cfb8();
        if ((*(uint *)(*(int *)(puVar10 + 0x28) + 0x44) & 0x800) == 0) {
          bVar1 = *(byte *)(*(int *)(puVar10 + 0x28) + 0x5f);
          if ((bVar1 & 1) == 0) {
            if ((bVar1 & 0x80) != 0) {
              uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar15),FUN_80074694);
            }
          }
          else {
            uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar15),FUN_80073e80);
          }
        }
        else {
          uVar20 = FUN_80028600(*(int *)(*(int *)(puVar10 + 0x3e) + iVar15),FUN_80074e80);
        }
      }
    }
    uVar3 = FUN_80022ee8(*(int *)(puVar10 + 0x3e) + *(char *)(iVar6 + 0x55) * 4);
    uVar11 = puVar10[0x23];
    if ((uVar11 == 0x1f) || (((short)uVar11 < 0x1f && (uVar11 == 0)))) {
      iVar15 = 0x8e0;
    }
    else if ((*(int **)(puVar10 + 0x34) == (int *)0x0) ||
            (pcVar13 = *(code **)(**(int **)(puVar10 + 0x34) + 0x1c), pcVar13 == (code *)0x0)) {
      iVar15 = 0;
    }
    else {
      iVar15 = (*pcVar13)(puVar10,uVar3);
      uVar20 = extraout_f1_04;
    }
    if (iVar15 == 0) {
      puVar10[0x5c] = 0;
      puVar10[0x5d] = 0;
    }
    else {
      *(uint *)(puVar10 + 0x5c) = uVar3;
      uVar3 = uVar3 + iVar15;
    }
    if (((uVar7 & 0x40) != 0) || ((*(uint *)(*(int *)(puVar10 + 0x28) + 0x44) & 0x400000) != 0)) {
      uVar11 = puVar10[0x23];
      uVar3 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x30) = uVar3;
      uVar3 = FUN_80022f00(uVar3 + 8);
      *(uint *)(*(int *)(puVar10 + 0x30) + 4) = uVar3;
      uVar20 = FUN_8002c7a0(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                            (int)puVar10,(int)(short)uVar11,*(uint **)(puVar10 + 0x30),0,1,param_14,
                            param_15,param_16);
      uVar3 = uVar3 + 0x50;
    }
    if (((uVar7 & 0x100) != 0) && (**(int **)(puVar10 + 0x3e) != 0)) {
      uVar3 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x2e) = uVar3;
      uVar3 = FUN_80022f00(uVar3 + 8);
      *(uint *)(*(int *)(puVar10 + 0x2e) + 4) = uVar3;
      uVar3 = uVar3 + 0x800;
    }
    if (((uVar7 & 2) != 0) && (*(short *)(iVar6 + 0x48) != 0)) {
      uVar3 = FUN_80062a60(uVar20,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)puVar10,uVar3);
    }
    dVar21 = (double)FLOAT_803df54c;
    iVar15 = 0;
    for (iVar14 = 0; iVar14 < *(char *)(*(int *)(puVar10 + 0x28) + 0x55); iVar14 = iVar14 + 1) {
      piVar18 = *(int **)(*(int *)(puVar10 + 0x3e) + iVar15);
      if (piVar18 != (int *)0x0) {
        uVar11 = FUN_800284f8(*piVar18);
        uStack_4c = (uint)uVar11;
        local_50 = 0x43300000;
        if (dVar21 < (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df528)) {
          uVar11 = FUN_800284f8(*piVar18);
          uStack_4c = (uint)uVar11;
          local_50 = 0x43300000;
          dVar21 = (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803df528);
        }
      }
      iVar15 = iVar15 + 4;
    }
    uVar7 = (uint)*(byte *)(*(int *)(puVar10 + 0x28) + 0x73);
    if (uVar7 != 0) {
      local_50 = 0x43300000;
      dVar21 = (double)(float)(dVar21 * (double)((FLOAT_803df54c *
                                                 (float)((double)CONCAT44(0x43300000,uVar7) -
                                                        DOUBLE_803df528)) / FLOAT_803df550));
      uStack_4c = uVar7;
    }
    *(float *)(puVar10 + 0x54) = (float)dVar21;
    if ((*(char *)(iVar6 + 0x61) != '\0') &&
       (uVar3 = FUN_800360c4((int)puVar10,uVar3), (*(byte *)(iVar6 + 0x65) & 8) != 0)) {
      uVar3 = FUN_800357e8(puVar10,uVar3);
    }
    if (*(char *)(iVar6 + 0x5a) != '\0') {
      uVar3 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x36) = uVar3;
      uVar3 = uVar3 + (uint)*(byte *)(iVar6 + 0x5a) * 0x12;
    }
    if (*(char *)(iVar6 + 0x59) != '\0') {
      uVar3 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x38) = uVar3;
      uVar3 = uVar3 + (uint)*(byte *)(iVar6 + 0x59) * 0x10;
    }
    if (*(char *)(iVar6 + 0x72) != '\0') {
      uVar3 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x3a) = uVar3;
      uVar3 = uVar3 + (uint)*(byte *)(iVar6 + 0x72) * 0x18;
    }
    if ((*(char *)(iVar6 + 0x61) != '\0') && (*(char *)(iVar6 + 0x66) != '\0')) {
      uVar7 = FUN_80022ee8(uVar3);
      uVar3 = FUN_80035920((int)(short)puVar10[0x23],**(undefined4 **)(puVar10 + 0x3e),
                           *(int *)(puVar10 + 0x2a),uVar7,puVar10);
    }
    if (*(char *)(iVar6 + 0x72) != '\0') {
      uVar7 = FUN_80022ee8(uVar3);
      *(uint *)(puVar10 + 0x3c) = uVar7;
      iVar15 = 0;
      iVar14 = 0;
      for (iVar19 = 0; iVar19 < (int)(uint)*(byte *)(iVar6 + 0x72); iVar19 = iVar19 + 1) {
        *(undefined *)(*(int *)(puVar10 + 0x3c) + iVar14 + 4) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar15 + 0x10);
        *(undefined *)(*(int *)(puVar10 + 0x3c) + iVar14) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar15 + 0xc);
        *(undefined *)(*(int *)(puVar10 + 0x3c) + iVar14 + 3) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar15 + 0xf);
        *(undefined *)(*(int *)(puVar10 + 0x3c) + iVar14 + 1) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar15 + 0xd);
        *(undefined *)(*(int *)(puVar10 + 0x3c) + iVar14 + 2) =
             *(undefined *)(*(int *)(iVar6 + 0x40) + iVar15 + 0xe);
        iVar15 = iVar15 + 0x18;
        iVar14 = iVar14 + 5;
      }
    }
    *(uint **)(puVar10 + 0x18) = param_13;
  }
LAB_8002e068:
  FUN_80286870();
  return;
}

