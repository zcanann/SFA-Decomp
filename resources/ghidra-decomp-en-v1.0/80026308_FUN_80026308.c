// Function: FUN_80026308
// Entry: 80026308
// Size: 1160 bytes

/* WARNING: Removing unreachable block (ram,0x80026768) */
/* WARNING: Removing unreachable block (ram,0x80026770) */

void FUN_80026308(undefined4 param_1,undefined4 param_2,int param_3,int *param_4,code *param_5,
                 undefined4 param_6)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  float *pfVar5;
  uint uVar6;
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
  float local_c8;
  float local_c4;
  float local_c0;
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
  uVar16 = FUN_802860c0();
  piVar2 = (int *)((ulonglong)uVar16 >> 0x20);
  iVar4 = (int)*(char *)(*(int *)((int)uVar16 + 0x3c) + **(int **)param_4[1] * 0x1c);
  uVar6 = (uint)*(byte *)(*piVar2 + 0xf3);
  if (uVar6 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = uVar6 + *(byte *)(*piVar2 + 0xf4);
  }
  if (iVar1 <= iVar4) {
    iVar4 = 0;
  }
  FUN_80246e80(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar4 * 0x40,auStack128);
  iVar4 = **(int **)param_4[1];
  uVar6 = (uint)*(byte *)(*piVar2 + 0xf3);
  if (uVar6 == 0) {
    iVar1 = 1;
  }
  else {
    iVar1 = uVar6 + *(byte *)(*piVar2 + 0xf4);
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
    iVar3 = *param_4;
    pfVar5 = (float *)(iVar3 + iVar9);
    local_bc = (FLOAT_803dced0 + *pfVar5 + pfVar5[3]) - FLOAT_803dcdd8;
    local_b8 = pfVar5[1] + pfVar5[4];
    local_b4 = (FLOAT_803dcecc + pfVar5[2] + pfVar5[5]) - FLOAT_803dcddc;
    local_c8 = *(float *)(iVar3 + iVar9 + -0x3c);
    local_c4 = *(float *)(iVar3 + iVar9 + -0x38);
    local_c0 = *(float *)(iVar3 + iVar9 + -0x34);
    if (param_5 != (code *)0x0) {
      (*param_5)((double)*(float *)(param_3 + 0x14),(int)uVar16,piVar2,&local_c8,param_6,iVar1);
    }
    FUN_80247730(&local_c8,*param_4 + iVar9 + 0x18,&local_c8);
    FUN_80247494(auStack128,&local_c8,&local_c8);
    FUN_80247754(&local_bc,&local_d4,auStack236);
    FUN_80247794(auStack236,auStack236);
    FUN_80247754(&local_c8,&local_d4,auStack224);
    FUN_80247794(auStack224,auStack224);
    dVar13 = (double)FUN_8024782c(auStack224,auStack236);
    if ((dVar15 <= dVar13) || (dVar13 <= (double)FLOAT_803de83c)) {
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
    FUN_80246eb4(auStack128,iVar4,iVar4);
    *(undefined4 *)(iVar4 + 0xc) = local_d4;
    *(undefined4 *)(iVar4 + 0x1c) = local_d0;
    *(undefined4 *)(iVar4 + 0x2c) = local_cc;
    FUN_80246e80(iVar4,auStack128);
    iVar3 = *param_4;
    local_c8 = *(float *)(iVar3 + iVar9 + 0x18);
    local_c4 = *(float *)(iVar3 + iVar9 + 0x1c);
    local_c0 = *(float *)(iVar3 + iVar9 + 0x20);
    FUN_80247494(iVar4,&local_c8,&local_c8);
    FUN_80246e80(iVar4,*param_4 + iVar8 + 0x24);
    if (iVar1 < param_4[2]) {
      uVar6 = (uint)*(byte *)(*piVar2 + 0xf3);
      if (uVar6 == 0) {
        iVar4 = 1;
      }
      else {
        iVar4 = uVar6 + *(byte *)(*piVar2 + 0xf4);
      }
      if (iVar4 <= iVar7) {
        iVar7 = 0;
      }
      iVar4 = piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar7 * 0x40;
    }
    ((float *)(*param_4 + iVar9))[3] =
         local_c8 - ((FLOAT_803dced0 + *(float *)(*param_4 + iVar9)) - FLOAT_803dcdd8);
    *(float *)(*param_4 + iVar9 + 0x10) = local_c4 - *(float *)(*param_4 + iVar9 + 4);
    *(float *)(*param_4 + iVar9 + 0x14) =
         local_c0 - ((FLOAT_803dcecc + *(float *)(*param_4 + iVar9 + 8)) - FLOAT_803dcddc);
    *(float *)(*param_4 + iVar9) = local_c8;
    *(float *)(*param_4 + iVar9 + 4) = local_c4;
    *(float *)(*param_4 + iVar9 + 8) = local_c0;
    iVar10 = iVar10 + 4;
    iVar9 = iVar9 + 0x54;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_8028610c();
  return;
}

