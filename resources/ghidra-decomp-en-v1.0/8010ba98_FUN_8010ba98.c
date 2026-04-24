// Function: FUN_8010ba98
// Entry: 8010ba98
// Size: 1128 bytes

/* WARNING: Removing unreachable block (ram,0x8010bed8) */
/* WARNING: Removing unreachable block (ram,0x8010bec8) */
/* WARNING: Removing unreachable block (ram,0x8010beb8) */
/* WARNING: Removing unreachable block (ram,0x8010beb0) */
/* WARNING: Removing unreachable block (ram,0x8010bec0) */
/* WARNING: Removing unreachable block (ram,0x8010bed0) */
/* WARNING: Removing unreachable block (ram,0x8010bee0) */

void FUN_8010ba98(undefined4 param_1,undefined4 param_2,undefined4 *param_3)

{
  short *psVar1;
  undefined4 uVar2;
  int iVar3;
  short sVar4;
  short sVar5;
  int iVar6;
  short sVar7;
  undefined4 uVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  undefined8 in_f25;
  double dVar15;
  undefined8 in_f26;
  double dVar16;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  undefined8 uVar18;
  undefined4 local_148;
  undefined4 local_144;
  undefined auStack320 [16];
  undefined auStack304 [16];
  undefined auStack288 [16];
  undefined auStack272 [16];
  undefined auStack256 [16];
  undefined auStack240 [16];
  undefined auStack224 [16];
  undefined auStack208 [16];
  undefined auStack192 [16];
  float local_b0;
  float local_ac;
  float local_a8;
  longlong local_a0;
  double local_98;
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
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
  uVar18 = FUN_802860d8();
  psVar1 = (short *)((ulonglong)uVar18 >> 0x20);
  iVar6 = *(int *)(psVar1 + 0x52);
  if (DAT_803dd560 == 0) {
    DAT_803dd560 = FUN_80023cc8(0x68,0xf,0);
  }
  FUN_800033a8(DAT_803dd560,0,0x68);
  *(undefined4 *)(DAT_803dd560 + 4) = *param_3;
  *(undefined *)(DAT_803dd560 + 100) = 1;
  local_148 = 9;
  local_144 = 0x1b;
  uVar2 = (**(code **)(*DAT_803dca9c + 0x14))
                    ((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                     (double)*(float *)(iVar6 + 0x20),&local_148,2,*(undefined4 *)(DAT_803dd560 + 4)
                    );
  *(undefined4 *)(DAT_803dd560 + 0xc) = uVar2;
  local_148 = 8;
  local_144 = 0x1a;
  uVar2 = (**(code **)(*DAT_803dca9c + 0x14))
                    ((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                     (double)*(float *)(iVar6 + 0x20),&local_148,2,*(undefined4 *)(DAT_803dd560 + 4)
                    );
  *(undefined4 *)(DAT_803dd560 + 8) = uVar2;
  FUN_8010a104((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
               (double)*(float *)(iVar6 + 0x20),DAT_803dd560 + 0xc,DAT_803dd560 + 8,
               *(undefined4 *)(DAT_803dd560 + 4));
  iVar3 = (**(code **)(*DAT_803dca9c + 0x1c))(*(undefined4 *)(DAT_803dd560 + 8));
  uVar2 = (**(code **)(*DAT_803dca9c + 0x1c))(*(undefined4 *)(DAT_803dd560 + 0xc));
  FUN_8010aa54(iVar3,auStack208,*(undefined4 *)(DAT_803dd560 + 4));
  FUN_8010aa54(uVar2,auStack192,*(undefined4 *)(DAT_803dd560 + 4));
  FUN_8010a590(auStack208,auStack288,auStack304,auStack320,auStack224,auStack240,auStack256,
               auStack272);
  dVar10 = (double)FUN_8010ac48((double)*(float *)(iVar6 + 0x18),(double)*(float *)(iVar6 + 0x1c),
                                (double)*(float *)(iVar6 + 0x20),auStack192);
  dVar9 = (double)FLOAT_803e1888;
  if ((dVar9 <= dVar10) && (dVar9 = dVar10, (double)FLOAT_803e188c < dVar10)) {
    dVar9 = (double)FLOAT_803e188c;
  }
  dVar10 = (double)FUN_80010ee0(dVar9,auStack288,0);
  dVar11 = (double)FUN_80010ee0(dVar9,auStack304,0);
  dVar12 = (double)FUN_80010ee0(dVar9,auStack320,0);
  dVar17 = (double)(float)(dVar10 - (double)*(float *)(iVar6 + 0x18));
  dVar16 = (double)(float)(dVar11 - (double)*(float *)(iVar6 + 0x1c));
  dVar15 = (double)(float)(dVar12 - (double)*(float *)(iVar6 + 0x20));
  if ((*(byte *)(iVar3 + 0x3b) & 1) == 0) {
    dVar13 = (double)FUN_80010c64(dVar9,auStack224,0);
    local_a0 = (longlong)(int)dVar13;
    sVar4 = (short)(int)dVar13;
  }
  else {
    sVar4 = FUN_800217c0(dVar17,dVar15);
    sVar4 = -sVar4;
  }
  if ((*(byte *)(iVar3 + 0x3b) & 4) == 0) {
    dVar13 = (double)FUN_80010c64(dVar9,auStack256,0);
    local_98 = (double)(longlong)(int)dVar13;
    sVar7 = (short)(int)dVar13;
  }
  else {
    sVar7 = *(short *)(iVar6 + 4);
  }
  if ((*(byte *)(iVar3 + 0x3b) & 2) == 0) {
    dVar15 = (double)FUN_80010c64(dVar9,auStack240,0);
    local_98 = (double)(longlong)(int)dVar15;
    sVar5 = (short)(int)dVar15;
  }
  else {
    uVar14 = FUN_802931a0((double)(float)(dVar17 * dVar17 + (double)(float)(dVar15 * dVar15)));
    sVar5 = FUN_800217c0(dVar16,uVar14);
    dVar15 = (double)FUN_80010c64(dVar9,auStack240,0);
    local_98 = (double)CONCAT44(0x43300000,(int)sVar5 ^ 0x80000000);
    iVar6 = (int)((double)(float)(local_98 - DOUBLE_803e18a0) - dVar15);
    local_a0 = (longlong)iVar6;
    sVar5 = (short)iVar6;
  }
  dVar15 = (double)FUN_80010ee0(dVar9,auStack272,0);
  local_b0 = (float)dVar10;
  local_ac = (float)dVar11;
  local_a8 = (float)dVar12;
  if ((*(char *)(param_3 + 1) == '\0') && ((int)uVar18 != 3)) {
    FUN_8010b238(psVar1,&local_b0,(int)(short)(sVar4 + -0x8000),(int)sVar5,(int)sVar7);
  }
  else {
    *(float *)(psVar1 + 0xc) = (float)dVar10;
    *(float *)(psVar1 + 0xe) = (float)dVar11;
    *(float *)(psVar1 + 0x10) = (float)dVar12;
    FUN_8000e034((double)*(float *)(psVar1 + 0xc),(double)*(float *)(psVar1 + 0xe),
                 (double)*(float *)(psVar1 + 0x10),psVar1 + 6,psVar1 + 8,psVar1 + 10,
                 *(undefined4 *)(psVar1 + 0x18));
    *psVar1 = sVar4 + -0x8000;
    psVar1[1] = sVar5;
    psVar1[2] = sVar7;
    *(float *)(psVar1 + 0x5a) = (float)dVar15;
  }
  *(float *)(DAT_803dd560 + 0x58) = (float)dVar9;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  __psq_l0(auStack88,uVar8);
  __psq_l1(auStack88,uVar8);
  __psq_l0(auStack104,uVar8);
  __psq_l1(auStack104,uVar8);
  FUN_80286124();
  return;
}

