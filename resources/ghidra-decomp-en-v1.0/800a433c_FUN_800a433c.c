// Function: FUN_800a433c
// Entry: 800a433c
// Size: 1764 bytes

/* WARNING: Removing unreachable block (ram,0x800a49f8) */
/* WARNING: Removing unreachable block (ram,0x800a49e8) */
/* WARNING: Removing unreachable block (ram,0x800a49d8) */
/* WARNING: Removing unreachable block (ram,0x800a49e0) */
/* WARNING: Removing unreachable block (ram,0x800a49f0) */
/* WARNING: Removing unreachable block (ram,0x800a4a00) */

void FUN_800a433c(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  int iVar7;
  uint uVar8;
  undefined *puVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  int iVar13;
  short sVar14;
  short sVar15;
  int *piVar16;
  undefined4 uVar17;
  undefined8 in_f26;
  undefined8 in_f27;
  double dVar18;
  double dVar19;
  undefined8 in_f28;
  double dVar20;
  undefined8 in_f29;
  double dVar21;
  undefined8 in_f30;
  double dVar22;
  undefined8 in_f31;
  double dVar23;
  undefined8 uVar24;
  undefined2 local_e0;
  undefined2 local_de;
  undefined2 local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  int local_b0;
  undefined4 *local_ac;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar17 = 0;
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
  uVar24 = FUN_802860b4();
  uVar6 = (undefined4)((ulonglong)uVar24 >> 0x20);
  iVar7 = FUN_8001ffb4(0x468);
  if (iVar7 != 0) {
    FUN_800200e8(0x468,0);
    DAT_803dd2bc = 0xf;
    FUN_8000bb18(param_3,0x281);
  }
  piVar16 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (6 < DAT_803dd2b4) {
    DAT_803dd2b4 = 0;
  }
  if ((int)(*(byte *)(*piVar16 + 0xf3) - 1) < DAT_803dd2b0) {
    DAT_803dd2b0 = 0;
  }
  DAT_803dd2b8 = DAT_803dd2b8 + (uint)DAT_803db410;
  if (0x1f < DAT_803dd2b8) {
    DAT_803dd2b8 = DAT_803dd2b8 + -0x1f;
  }
  FLOAT_803dd2ac = FLOAT_803db798 * FLOAT_803db414 + FLOAT_803dd2ac;
  if (FLOAT_803dd2ac <= FLOAT_803df4ac) {
    if (FLOAT_803dd2ac < FLOAT_803df4b4) {
      FLOAT_803db798 = FLOAT_803db798 * FLOAT_803df4b0;
      FLOAT_803dd2ac = FLOAT_803df4b4;
      FUN_8000bb18(param_3,0x282);
    }
  }
  else {
    FLOAT_803db798 = FLOAT_803db798 * FLOAT_803df4b0;
    FLOAT_803dd2ac = FLOAT_803df4ac;
    FUN_8000bb18(param_3,0x282);
  }
  local_b0 = 0;
  piVar5 = &DAT_8039c2c0;
  local_ac = &DAT_8039c2c0;
  do {
    if (local_b0 != 5) {
      DAT_803dd2b4 = (short)local_b0;
      iVar7 = 0;
      puVar9 = &DAT_803103ec;
      dVar21 = (double)FLOAT_803df4a8;
      dVar22 = (double)FLOAT_803df4b8;
      dVar23 = (double)FLOAT_803df4bc;
      for (sVar15 = 0; sVar15 < 5; sVar15 = sVar15 + 1) {
        local_d4 = (float)dVar21;
        local_d0 = (float)dVar21;
        local_cc = (float)dVar21;
        local_d8 = (float)dVar22;
        local_dc = 0;
        local_de = 0;
        local_e0 = 0;
        uVar8 = (uint)(byte)(&DAT_803103ec)[DAT_803dd2b4 * 5 + (int)sVar15];
        iVar13 = piVar16[(*(ushort *)(piVar16 + 6) & 1) + 3] + uVar8 * 0x100;
        dVar18 = (double)(*(float *)(iVar13 + 0x34) - *(float *)(param_3 + 0x10));
        dVar20 = (double)(float)((double)((*(float *)(iVar13 + 0x30) + FLOAT_803dcdd8) -
                                         *(float *)(param_3 + 0xc)) * dVar23);
        if ((uVar8 == 0x1d) || (uVar8 == 0x1d)) {
          fVar2 = FLOAT_803df4bc * (float)((double)FLOAT_803df4c0 + dVar18);
        }
        else {
          fVar2 = (float)(dVar18 * dVar23);
        }
        dVar19 = (double)fVar2;
        dVar18 = (double)(float)((double)((*(float *)(iVar13 + 0x38) + FLOAT_803dcddc) -
                                         *(float *)(param_3 + 0x14)) * dVar23);
        FUN_800226cc((double)local_d4,(double)local_d0,(double)local_cc,iVar13,&local_d4,&local_d0,
                     &local_cc);
        pfVar12 = (float *)&DAT_8030fec8;
        pfVar10 = (float *)&DAT_8030ff58;
        pfVar11 = (float *)&DAT_8030fe38;
        for (sVar14 = 0; sVar14 < 4; sVar14 = sVar14 + 1) {
          uVar8 = (uint)(byte)puVar9[DAT_803dd2b4 * 5];
          cVar3 = (&DAT_803103c8)[uVar8];
          if (cVar3 == '\0') {
            local_d4 = *pfVar12 * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_d0 = pfVar12[1] * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_cc = pfVar12[2] * *(float *)(&DAT_8031049c + uVar8 * 4);
          }
          else if (cVar3 == '\x01') {
            local_d4 = *pfVar11 * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_d0 = pfVar11[1] * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_cc = pfVar11[2] * *(float *)(&DAT_8031049c + uVar8 * 4);
          }
          else if (cVar3 == '\x02') {
            local_d4 = *pfVar10 * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_d0 = pfVar10[1] * *(float *)(&DAT_80310410 + uVar8 * 4);
            local_cc = pfVar10[2] * *(float *)(&DAT_8031049c + uVar8 * 4);
          }
          FUN_800226cc((double)local_d4,(double)local_d0,(double)local_cc,iVar13,&local_d4,&local_d0
                       ,&local_cc);
          local_d4 = local_d4 + FLOAT_803dcdd8;
          local_cc = local_cc + FLOAT_803dcddc;
          iVar1 = (int)(dVar20 + (double)(local_d4 - *(float *)(param_3 + 0xc)));
          local_c8 = (longlong)iVar1;
          iVar4 = (sVar14 + iVar7) * 0x10;
          *(short *)(*piVar5 + iVar4) = (short)iVar1;
          iVar1 = (int)(dVar19 + (double)(local_d0 - *(float *)(param_3 + 0x10)));
          local_c0 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 2) = (short)iVar1;
          iVar1 = (int)(dVar18 + (double)(local_cc - *(float *)(param_3 + 0x14)));
          local_b8 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 4) = (short)iVar1;
          *(undefined *)(*piVar5 + iVar4 + 0xf) = 0x9b;
          *(short *)(*piVar5 + iVar4 + 10) =
               (&DAT_8030fff2)[(sVar14 + iVar7) * 8] - (short)(DAT_803dd2b8 << 2);
          pfVar12 = pfVar12 + 3;
          pfVar11 = pfVar11 + 3;
          pfVar10 = pfVar10 + 3;
        }
        iVar7 = iVar7 + 4;
        puVar9 = puVar9 + 1;
      }
    }
    piVar5 = piVar5 + 1;
    local_b0 = local_b0 + 1;
  } while (local_b0 < 7);
  local_d4 = *(float *)(param_3 + 0xc);
  local_d0 = *(float *)(param_3 + 0x10);
  local_cc = *(float *)(param_3 + 0x14);
  local_d8 = FLOAT_803df4c4;
  FUN_8005d118(uVar6,0xff,0xff,0xff,0xff);
  if (DAT_803dd2bc == 0) {
    FUN_800541ac(uVar6,DAT_803dd2a4,0,0,0,0,0);
  }
  else {
    (**(code **)(*DAT_803dca88 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    iVar7 = FUN_800221a0(0,1);
    if (iVar7 == 0) {
      FUN_800541ac(uVar6,DAT_803dd2a8,0,0,0,0,0);
    }
    else {
      FUN_800541ac(uVar6,DAT_803dd2a4,0,0,0,0,0);
    }
    DAT_803dd2bc = DAT_803dd2bc - (ushort)DAT_803db410;
    if (DAT_803dd2bc < 0) {
      DAT_803dd2bc = 0;
    }
  }
  FUN_8000e820((double)FLOAT_803df4b8,(double)FLOAT_803df4a8,uVar6,(int)uVar24,&local_e0,0);
  FUN_80258b24(0);
  FUN_8005d0e8(uVar6,0xff,0xff,0xff,0xff);
  FUN_800799c0();
  FUN_800796f0();
  FUN_80079254();
  FUN_80079804();
  FUN_80078b4c();
  iVar7 = 0;
  do {
    FUN_8005cf8c(*local_ac,&DAT_80310128,0x20);
    local_ac = local_ac + 1;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 7);
  DAT_803dd2a0 = 1 - DAT_803dd2a0;
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  __psq_l0(auStack40,uVar17);
  __psq_l1(auStack40,uVar17);
  __psq_l0(auStack56,uVar17);
  __psq_l1(auStack56,uVar17);
  __psq_l0(auStack72,uVar17);
  __psq_l1(auStack72,uVar17);
  __psq_l0(auStack88,uVar17);
  __psq_l1(auStack88,uVar17);
  FUN_80286100();
  return;
}

