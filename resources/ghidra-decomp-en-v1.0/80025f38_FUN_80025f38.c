// Function: FUN_80025f38
// Entry: 80025f38
// Size: 976 bytes

/* WARNING: Removing unreachable block (ram,0x800262e0) */
/* WARNING: Removing unreachable block (ram,0x800262e8) */

void FUN_80025f38(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)

{
  int iVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  undefined auStack248 [12];
  undefined auStack236 [12];
  undefined auStack224 [12];
  undefined4 local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined auStack176 [48];
  undefined auStack128 [104];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar16 = FUN_802860cc();
  piVar2 = (int *)((ulonglong)uVar16 >> 0x20);
  iVar4 = (int)*(char *)(*(int *)((int)uVar16 + 0x3c) + **(int **)param_4[1] * 0x1c);
  uVar5 = (uint)*(byte *)(*piVar2 + 0xf3);
  if (uVar5 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = uVar5 + *(byte *)(*piVar2 + 0xf4);
  }
  if (iVar1 <= iVar4) {
    iVar4 = 0;
  }
  FUN_80246e80(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar4 * 0x40,auStack128);
  iVar4 = **(int **)param_4[1];
  uVar5 = (uint)*(byte *)(*piVar2 + 0xf3);
  if (uVar5 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = uVar5 + *(byte *)(*piVar2 + 0xf4);
  }
  if (iVar1 <= iVar4) {
    iVar4 = 0;
  }
  iVar4 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar4 * 0x40;
  iVar10 = 4;
  iVar9 = 0x54;
  dVar15 = (double)FLOAT_803de838;
  for (iVar1 = 1; iVar1 < param_4[2] + 1; iVar1 = iVar1 + 1) {
    iVar7 = *(int *)(*(int *)param_4[1] + iVar10);
    iVar8 = (iVar1 + -1) * 0x54;
    FUN_80247494(auStack128,*param_4 + iVar8 + 0x18,&local_d4);
    iVar6 = *param_4;
    pfVar3 = (float *)(iVar6 + iVar9);
    local_bc = (FLOAT_803dced0 + *pfVar3 + pfVar3[3]) - FLOAT_803dcdd8;
    local_b8 = pfVar3[1] + pfVar3[4];
    local_b4 = (FLOAT_803dcecc + pfVar3[2] + pfVar3[5]) - FLOAT_803dcddc;
    local_c8 = *(undefined4 *)(iVar6 + iVar9 + -0x3c);
    local_c4 = *(undefined4 *)(iVar6 + iVar9 + -0x38);
    local_c0 = *(undefined4 *)(iVar6 + iVar9 + -0x34);
    FUN_80247730(&local_c8,iVar6 + iVar9 + 0x18,&local_c8);
    FUN_80247494(auStack128,&local_c8,&local_c8);
    FUN_80247754(&local_bc,&local_d4,auStack236);
    FUN_80247794(auStack236,auStack236);
    FUN_80247754(&local_c8,&local_d4,auStack224);
    FUN_80247794(auStack224,auStack224);
    dVar13 = (double)FUN_8024782c(auStack224,auStack236);
    if ((dVar13 < dVar15) && ((double)FLOAT_803de83c < dVar13)) {
      if (((double)FLOAT_803de818 <= dVar13) || (dVar13 <= (double)FLOAT_803de840)) {
        FUN_80246e54(iVar4);
      }
      else {
        dVar14 = (double)FUN_8024784c(auStack224,auStack236,auStack248);
        dVar12 = (double)FLOAT_803de840;
        if (dVar12 <= dVar13) {
          dVar14 = (double)(float)((double)FLOAT_803de818 - dVar13);
          dVar12 = (double)(float)(dVar14 * (double)*(float *)(param_3 + 8) + dVar13);
        }
        FUN_80246f80(dVar14,auStack128,auStack176);
        FUN_80247574(auStack176,auStack248,auStack248);
        FUN_802920a4(dVar12);
        FUN_802471e0(iVar4,auStack248);
      }
    }
    FUN_80246eb4(auStack128,iVar4,iVar4);
    *(undefined4 *)(iVar4 + 0xc) = local_d4;
    *(undefined4 *)(iVar4 + 0x1c) = local_d0;
    *(undefined4 *)(iVar4 + 0x2c) = local_cc;
    FUN_80246e80(iVar4,auStack128);
    iVar6 = *param_4;
    local_c8 = *(undefined4 *)(iVar6 + iVar9 + 0x18);
    local_c4 = *(undefined4 *)(iVar6 + iVar9 + 0x1c);
    local_c0 = *(undefined4 *)(iVar6 + iVar9 + 0x20);
    FUN_80247494(iVar4,&local_c8,&local_c8);
    FUN_80246e80(iVar4,*param_4 + iVar8 + 0x24);
    if (iVar1 < param_4[2]) {
      uVar5 = (uint)*(byte *)(*piVar2 + 0xf3);
      if (uVar5 == 0) {
        iVar4 = 1;
      }
      else {
        iVar4 = uVar5 + *(byte *)(*piVar2 + 0xf4);
      }
      if (iVar4 <= iVar7) {
        iVar7 = 0;
      }
      iVar4 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar7 * 0x40;
    }
    iVar10 = iVar10 + 4;
    iVar9 = iVar9 + 0x54;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_80286118();
  return;
}

