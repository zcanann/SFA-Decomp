// Function: FUN_8006d19c
// Entry: 8006d19c
// Size: 1480 bytes

/* WARNING: Removing unreachable block (ram,0x8006d744) */
/* WARNING: Removing unreachable block (ram,0x8006d73c) */
/* WARNING: Removing unreachable block (ram,0x8006d734) */
/* WARNING: Removing unreachable block (ram,0x8006d72c) */
/* WARNING: Removing unreachable block (ram,0x8006d724) */
/* WARNING: Removing unreachable block (ram,0x8006d71c) */
/* WARNING: Removing unreachable block (ram,0x8006d714) */
/* WARNING: Removing unreachable block (ram,0x8006d70c) */
/* WARNING: Removing unreachable block (ram,0x8006d1e4) */
/* WARNING: Removing unreachable block (ram,0x8006d1dc) */
/* WARNING: Removing unreachable block (ram,0x8006d1d4) */
/* WARNING: Removing unreachable block (ram,0x8006d1cc) */
/* WARNING: Removing unreachable block (ram,0x8006d1c4) */
/* WARNING: Removing unreachable block (ram,0x8006d1bc) */
/* WARNING: Removing unreachable block (ram,0x8006d1b4) */
/* WARNING: Removing unreachable block (ram,0x8006d1ac) */

void FUN_8006d19c(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  uint uVar5;
  float *pfVar6;
  int iVar7;
  uint uVar8;
  float *pfVar9;
  uint uVar10;
  int iVar11;
  float *pfVar12;
  int *piVar13;
  float *pfVar14;
  uint uVar15;
  double dVar16;
  double dVar17;
  double in_f24;
  double in_f25;
  double in_f26;
  double in_f27;
  double dVar18;
  double dVar19;
  double in_f28;
  double in_f29;
  double dVar20;
  double in_f30;
  double dVar21;
  double in_f31;
  double dVar22;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_ec;
  float local_e8 [2];
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined8 local_d0;
  longlong local_c8;
  undefined8 local_c0;
  float local_78;
  float fStack_74;
  float local_68;
  float fStack_64;
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
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  FUN_80286820();
  uVar5 = FUN_80022e00(1);
  uVar15 = 0;
  iVar11 = 0;
  dVar21 = (double)FLOAT_803df9ac;
  dVar22 = (double)FLOAT_803df9a8;
  dVar20 = (double)FLOAT_803dfa5c;
  dVar18 = (double)FLOAT_803dfa58;
  pfVar14 = (float *)&DAT_803925d8;
  dVar19 = DOUBLE_803dfa48;
  while ((iVar11 < 0x32 && (uVar15 < 10000))) {
    uStack_dc = FUN_80022264(8,0x10);
    uStack_dc = uStack_dc ^ 0x80000000;
    local_e0 = 0x43300000;
    *pfVar14 = (float)((double)CONCAT44(0x43300000,uStack_dc) - dVar19);
    uStack_d4 = FUN_80022264(5,10);
    uStack_d4 = uStack_d4 ^ 0x80000000;
    local_d8 = 0x43300000;
    pfVar14[3] = (float)(dVar18 * (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19));
    uVar15 = FUN_80022264(0x14,0x32);
    local_d0 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
    pfVar14[4] = pfVar14[3] * (float)(dVar18 * (double)(float)(local_d0 - dVar19));
    uVar15 = 0;
    pfVar9 = pfVar14 + 1;
    pfVar12 = pfVar14 + 2;
    do {
      uVar10 = FUN_80022264(0,999);
      local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      *pfVar9 = (float)(dVar20 * (double)(float)(local_d0 - dVar19));
      uStack_d4 = FUN_80022264(0,999);
      uStack_d4 = uStack_d4 ^ 0x80000000;
      local_d8 = 0x43300000;
      *pfVar12 = (float)(dVar20 * (double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19));
      bVar4 = false;
      iVar7 = 0;
      pfVar6 = (float *)&DAT_803925d8;
      while ((iVar7 < iVar11 && (!bVar4))) {
        fVar1 = ABS((float)((double)*pfVar9 - (double)pfVar6[1]));
        fVar2 = ABS((float)((double)(float)(dVar21 + (double)*pfVar9) - (double)pfVar6[1]));
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar9 - dVar21) - pfVar6[1]);
        if (fVar2 < fVar1) {
          fVar1 = fVar2;
        }
        fVar2 = ABS((float)((double)*pfVar12 - (double)pfVar6[2]));
        fVar3 = ABS((float)((double)(float)(dVar21 + (double)*pfVar12) - (double)pfVar6[2]));
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        fVar3 = ABS((float)((double)*pfVar12 - dVar21) - pfVar6[2]);
        if (fVar3 < fVar2) {
          fVar2 = fVar3;
        }
        dVar17 = (double)(fVar1 * fVar1 + fVar2 * fVar2);
        if (dVar22 < dVar17) {
          dVar16 = 1.0 / SQRT(dVar17);
          dVar16 = DOUBLE_803df9d8 * dVar16 * -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0);
          dVar16 = DOUBLE_803df9d8 * dVar16 * -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0);
          dVar17 = (double)(float)(dVar17 * DOUBLE_803df9d8 * dVar16 *
                                            -(dVar17 * dVar16 * dVar16 - DOUBLE_803df9e0));
        }
        if (dVar17 < (double)(pfVar14[4] + pfVar6[3])) {
          bVar4 = true;
        }
        pfVar6 = pfVar6 + 5;
        iVar7 = iVar7 + 1;
      }
      uVar15 = uVar15 + 1;
    } while ((bVar4) && (uVar15 < 10000));
    pfVar14 = pfVar14 + 5;
    iVar11 = iVar11 + 1;
  }
  uVar15 = 0;
  piVar13 = &DAT_8038eec8;
  dVar20 = (double)FLOAT_803dfa60;
  dVar18 = (double)FLOAT_803df988;
  dVar19 = DOUBLE_803dfa48;
  do {
    iVar7 = FUN_80054e14(0x40,0x40,3,'\0',0,1,1,1,1);
    *piVar13 = iVar7;
    uVar10 = 0;
    do {
      uVar8 = 0;
      do {
        iVar7 = *piVar13;
        local_d0 = (double)CONCAT44(0x43300000,uVar10 ^ 0x80000000);
        uStack_d4 = uVar8 ^ 0x80000000;
        local_d8 = 0x43300000;
        local_e0 = 0x43300000;
        uStack_dc = uVar15 ^ 0x80000000;
        FUN_8006ce9c((double)(float)((double)(float)(local_d0 - dVar19) * dVar20),
                     (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_d4) - dVar19
                                                    ) * dVar20),
                     (double)(float)((double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - dVar19),
                     (float *)&DAT_803925d8,iVar11,local_e8,&local_ec);
        local_c8 = (longlong)(int)(dVar18 * (double)local_ec);
        local_c0 = (longlong)(int)(dVar18 * (double)local_e8[0]);
        *(ushort *)
         (iVar7 + (uVar10 & 3) * 2 + ((int)uVar10 >> 2) * 0x20 + (uVar8 & 3) * 8 +
          ((int)uVar8 >> 2) * 0x200 + 0x60) =
             (ushort)(((int)(dVar18 * (double)local_ec) & 0xffffU) << 8) |
             (ushort)(int)(dVar18 * (double)local_e8[0]);
        uVar8 = uVar8 + 1;
      } while ((int)uVar8 < 0x40);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    FUN_802420e0(*piVar13 + 0x60,*(int *)(*piVar13 + 0x44));
    piVar13 = piVar13 + 1;
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x10);
  DAT_803ddc60 = FUN_80054e14(0x40,0x40,3,'\0',0,1,1,1,1);
  uVar15 = 0;
  dVar19 = (double)FLOAT_803dfa40;
  do {
    uVar10 = 0;
    do {
      iVar7 = DAT_803ddc60 + (uVar15 & 3) * 2;
      local_c0 = CONCAT44(0x43300000,uVar10 ^ 0x80000000);
      FUN_802947f8();
      dVar18 = (double)FUN_80294b54();
      dVar20 = (double)FUN_80294b54();
      iVar11 = (int)(dVar19 * dVar18 + dVar19);
      local_c8 = (longlong)iVar11;
      uVar8 = (uint)(dVar19 * (double)(float)(dVar18 * dVar20) + dVar19);
      local_d0 = (double)(longlong)(int)uVar8;
      *(ushort *)
       (iVar7 + ((int)uVar15 >> 2) * 0x20 + (uVar10 & 3) * 8 + ((int)uVar10 >> 2) * 0x200 + 0x60) =
           (ushort)iVar11 | (ushort)((uVar8 & 0xffff) << 8);
      uVar10 = uVar10 + 1;
    } while ((int)uVar10 < 0x40);
    uVar15 = uVar15 + 1;
  } while ((int)uVar15 < 0x40);
  FUN_802420e0(DAT_803ddc60 + 0x60,*(int *)(DAT_803ddc60 + 0x44));
  FLOAT_803ddc2c = FLOAT_803df9a8;
  FLOAT_803ddc28 = FLOAT_803df9a8;
  FUN_80022e00(uVar5 & 0xff);
  FUN_8028686c();
  return;
}

