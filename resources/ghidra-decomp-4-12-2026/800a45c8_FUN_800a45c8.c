// Function: FUN_800a45c8
// Entry: 800a45c8
// Size: 1764 bytes

/* WARNING: Removing unreachable block (ram,0x800a4c8c) */
/* WARNING: Removing unreachable block (ram,0x800a4c84) */
/* WARNING: Removing unreachable block (ram,0x800a4c7c) */
/* WARNING: Removing unreachable block (ram,0x800a4c74) */
/* WARNING: Removing unreachable block (ram,0x800a4c6c) */
/* WARNING: Removing unreachable block (ram,0x800a4c64) */
/* WARNING: Removing unreachable block (ram,0x800a4600) */
/* WARNING: Removing unreachable block (ram,0x800a45f8) */
/* WARNING: Removing unreachable block (ram,0x800a45f0) */
/* WARNING: Removing unreachable block (ram,0x800a45e8) */
/* WARNING: Removing unreachable block (ram,0x800a45e0) */
/* WARNING: Removing unreachable block (ram,0x800a45d8) */

void FUN_800a45c8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int *piVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined *puVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  int iVar13;
  short sVar14;
  short sVar15;
  int *piVar16;
  double in_f26;
  double in_f27;
  double dVar17;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar23;
  ushort local_e0 [4];
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  longlong local_c8;
  longlong local_c0;
  longlong local_b8;
  int local_b0;
  int *local_ac;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  uVar23 = FUN_80286818();
  uVar6 = (undefined4)((ulonglong)uVar23 >> 0x20);
  uVar7 = FUN_80020078(0x468);
  if (uVar7 != 0) {
    FUN_800201ac(0x468,0);
    DAT_803ddf3c = 0xf;
    FUN_8000bb38(param_3,0x281);
  }
  piVar16 = *(int **)(*(int *)(param_3 + 0x7c) + *(char *)(param_3 + 0xad) * 4);
  if (6 < DAT_803ddf34) {
    DAT_803ddf34 = 0;
  }
  if ((int)(*(byte *)(*piVar16 + 0xf3) - 1) < DAT_803ddf30) {
    DAT_803ddf30 = 0;
  }
  DAT_803ddf38 = DAT_803ddf38 + (uint)DAT_803dc070;
  if (0x1f < DAT_803ddf38) {
    DAT_803ddf38 = DAT_803ddf38 + -0x1f;
  }
  FLOAT_803ddf2c = FLOAT_803dc3f8 * FLOAT_803dc074 + FLOAT_803ddf2c;
  if (FLOAT_803ddf2c <= FLOAT_803e012c) {
    if (FLOAT_803ddf2c < FLOAT_803e0134) {
      FLOAT_803dc3f8 = FLOAT_803dc3f8 * FLOAT_803e0130;
      FLOAT_803ddf2c = FLOAT_803e0134;
      FUN_8000bb38(param_3,0x282);
    }
  }
  else {
    FLOAT_803dc3f8 = FLOAT_803dc3f8 * FLOAT_803e0130;
    FLOAT_803ddf2c = FLOAT_803e012c;
    FUN_8000bb38(param_3,0x282);
  }
  local_b0 = 0;
  piVar5 = &DAT_8039cf20;
  local_ac = &DAT_8039cf20;
  do {
    if (local_b0 != 5) {
      DAT_803ddf34 = (short)local_b0;
      iVar13 = 0;
      puVar8 = &DAT_80310fac;
      dVar20 = (double)FLOAT_803e0128;
      dVar21 = (double)FLOAT_803e0138;
      dVar22 = (double)FLOAT_803e013c;
      for (sVar15 = 0; sVar15 < 5; sVar15 = sVar15 + 1) {
        local_d4 = (float)dVar20;
        local_d0 = (float)dVar20;
        local_cc = (float)dVar20;
        local_d8 = (float)dVar21;
        local_e0[2] = 0;
        local_e0[1] = 0;
        local_e0[0] = 0;
        uVar7 = (uint)(byte)(&DAT_80310fac)[DAT_803ddf34 * 5 + (int)sVar15];
        pfVar12 = (float *)(piVar16[(*(ushort *)(piVar16 + 6) & 1) + 3] + uVar7 * 0x100);
        dVar17 = (double)(pfVar12[0xd] - *(float *)(param_3 + 0x10));
        dVar19 = (double)(float)((double)((pfVar12[0xc] + FLOAT_803dda58) -
                                         *(float *)(param_3 + 0xc)) * dVar22);
        if ((uVar7 == 0x1d) || (uVar7 == 0x1d)) {
          fVar2 = FLOAT_803e013c * (float)((double)FLOAT_803e0140 + dVar17);
        }
        else {
          fVar2 = (float)(dVar17 * dVar22);
        }
        dVar18 = (double)fVar2;
        dVar17 = (double)(float)((double)((pfVar12[0xe] + FLOAT_803dda5c) -
                                         *(float *)(param_3 + 0x14)) * dVar22);
        FUN_80022790((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,&local_d0,
                     &local_cc);
        pfVar11 = (float *)&DAT_80310a88;
        pfVar9 = (float *)&DAT_80310b18;
        pfVar10 = (float *)&DAT_803109f8;
        for (sVar14 = 0; sVar14 < 4; sVar14 = sVar14 + 1) {
          uVar7 = (uint)(byte)puVar8[DAT_803ddf34 * 5];
          cVar3 = (&DAT_80310f88)[uVar7];
          if (cVar3 == '\0') {
            local_d4 = *pfVar11 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar11[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar11[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x01') {
            local_d4 = *pfVar10 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar10[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar10[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          else if (cVar3 == '\x02') {
            local_d4 = *pfVar9 * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_d0 = pfVar9[1] * *(float *)(&DAT_80310fd0 + uVar7 * 4);
            local_cc = pfVar9[2] * *(float *)(&DAT_8031105c + uVar7 * 4);
          }
          FUN_80022790((double)local_d4,(double)local_d0,(double)local_cc,pfVar12,&local_d4,
                       &local_d0,&local_cc);
          local_d4 = local_d4 + FLOAT_803dda58;
          local_cc = local_cc + FLOAT_803dda5c;
          iVar1 = (int)(dVar19 + (double)(local_d4 - *(float *)(param_3 + 0xc)));
          local_c8 = (longlong)iVar1;
          iVar4 = (sVar14 + iVar13) * 0x10;
          *(short *)(*piVar5 + iVar4) = (short)iVar1;
          iVar1 = (int)(dVar18 + (double)(local_d0 - *(float *)(param_3 + 0x10)));
          local_c0 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 2) = (short)iVar1;
          iVar1 = (int)(dVar17 + (double)(local_cc - *(float *)(param_3 + 0x14)));
          local_b8 = (longlong)iVar1;
          *(short *)(*piVar5 + iVar4 + 4) = (short)iVar1;
          *(undefined *)(*piVar5 + iVar4 + 0xf) = 0x9b;
          *(short *)(*piVar5 + iVar4 + 10) =
               (&DAT_80310bb2)[(sVar14 + iVar13) * 8] - (short)(DAT_803ddf38 << 2);
          pfVar11 = pfVar11 + 3;
          pfVar10 = pfVar10 + 3;
          pfVar9 = pfVar9 + 3;
        }
        iVar13 = iVar13 + 4;
        puVar8 = puVar8 + 1;
      }
    }
    piVar5 = piVar5 + 1;
    local_b0 = local_b0 + 1;
  } while (local_b0 < 7);
  local_d4 = *(float *)(param_3 + 0xc);
  local_d0 = *(float *)(param_3 + 0x10);
  local_cc = *(float *)(param_3 + 0x14);
  local_d8 = FLOAT_803e0144;
  FUN_8005d294(uVar6,0xff,0xff,0xff,0xff);
  if (DAT_803ddf3c == 0) {
    FUN_80054328(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
  }
  else {
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(param_3,0x28c,0,1,0xffffffff,0);
    uVar7 = FUN_80022264(0,1);
    if (uVar7 == 0) {
      FUN_80054328(uVar6,DAT_803ddf28,(undefined4 *)0x0,0,0);
    }
    else {
      FUN_80054328(uVar6,DAT_803ddf24,(undefined4 *)0x0,0,0);
    }
    DAT_803ddf3c = DAT_803ddf3c - (ushort)DAT_803dc070;
    if (DAT_803ddf3c < 0) {
      DAT_803ddf3c = 0;
    }
  }
  FUN_8000e840((double)FLOAT_803e0138,uVar6,(int)uVar23,local_e0,(float *)0x0);
  FUN_80259288(0);
  FUN_8005d264(uVar6,0xff,0xff,0xff,0xff);
  FUN_80079b3c();
  FUN_8007986c();
  FUN_800793d0();
  FUN_80079980();
  FUN_80078cc8();
  iVar13 = 0;
  do {
    FUN_8005d108(*local_ac,-0x7fcef318,0x20);
    local_ac = local_ac + 1;
    iVar13 = iVar13 + 1;
  } while (iVar13 < 7);
  DAT_803ddf20 = 1 - DAT_803ddf20;
  FUN_80286864();
  return;
}

