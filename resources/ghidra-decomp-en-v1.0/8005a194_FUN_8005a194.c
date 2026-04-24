// Function: FUN_8005a194
// Entry: 8005a194
// Size: 712 bytes

/* WARNING: Removing unreachable block (ram,0x8005a43c) */

undefined4 FUN_8005a194(int param_1)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined auStack72 [4];
  undefined auStack68 [4];
  float local_40;
  undefined auStack60 [4];
  undefined auStack56 [4];
  undefined auStack52 [4];
  double local_30;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if (*(byte *)(param_1 + 0x36) == 0) {
    *(undefined *)(param_1 + 0x37) = 0;
    uVar2 = 0;
    goto LAB_8005a43c;
  }
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 1) == 0)) {
    dVar10 = (double)*(float *)(param_1 + 0x40);
    if (dVar10 < (double)FLOAT_803debb8) {
      *(undefined *)(param_1 + 0x37) = 0;
      uVar2 = 0;
      goto LAB_8005a43c;
    }
    iVar3 = FUN_8002b9ec();
    if (((iVar5 == 0) || ((*(byte *)(iVar5 + 5) & 2) == 0)) || (iVar3 == 0)) {
      dVar9 = (double)FUN_8000f480((double)*(float *)(param_1 + 0x18),
                                   (double)*(float *)(param_1 + 0x1c),
                                   (double)*(float *)(param_1 + 0x20));
    }
    else {
      dVar9 = (double)FUN_80021704(param_1 + 0x18,iVar3 + 0x18);
    }
    if (dVar10 < dVar9) {
      *(undefined *)(param_1 + 0x37) = 0;
      uVar2 = 0;
      goto LAB_8005a43c;
    }
    uVar6 = 0xff;
    dVar8 = (double)(float)(dVar10 - (double)FLOAT_803debd4);
    if (dVar8 < dVar9) {
      uVar6 = (uint)(FLOAT_803debd8 *
                    (FLOAT_803debdc - (float)(dVar9 - dVar8) / (float)(dVar10 - dVar8)));
      local_30 = (double)(longlong)(int)uVar6;
    }
    FUN_8000eb88((double)(*(float *)(param_1 + 0x18) - FLOAT_803dcdd8),
                 (double)*(float *)(param_1 + 0x1c),
                 (double)(*(float *)(param_1 + 0x20) - FLOAT_803dcddc),
                 (double)(*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)),auStack52,auStack56,
                 auStack60,&local_40,auStack68,auStack72);
    fVar1 = ABS(local_40) * FLOAT_803debb4;
    if (fVar1 < FLOAT_803debe0) {
      *(undefined *)(param_1 + 0x37) = 0;
      uVar2 = 0;
      goto LAB_8005a43c;
    }
    if (fVar1 < FLOAT_803debe8) {
      local_30 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      uVar6 = (uint)(((float)(local_30 - DOUBLE_803debc0) * (fVar1 - FLOAT_803debe0)) /
                    FLOAT_803debe4);
    }
    *(char *)(param_1 + 0x37) = (char)(uVar6 * (*(byte *)(param_1 + 0x36) + 1) >> 8);
  }
  else {
    *(char *)(param_1 + 0x37) = (char)((*(byte *)(param_1 + 0x36) + 1) * 0xff >> 8);
  }
  if (*(char *)(param_1 + 0x37) == '\0') {
    uVar2 = 0;
  }
  else {
    for (bVar4 = 0; bVar4 < 5; bVar4 = bVar4 + 1) {
      uVar6 = (uint)bVar4;
      if (*(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8) +
          (float)(&DAT_80387948)[uVar6 * 5] +
          (float)(&DAT_80387944)[uVar6 * 5] * (*(float *)(param_1 + 0x20) - FLOAT_803dcddc) +
          *(float *)(param_1 + 0x1c) * (float)(&DAT_80387940)[uVar6 * 5] +
          (float)(&DAT_8038793c)[uVar6 * 5] * (*(float *)(param_1 + 0x18) - FLOAT_803dcdd8) <
          FLOAT_803debcc) {
        uVar2 = 0;
        goto LAB_8005a43c;
      }
    }
    uVar2 = 1;
  }
LAB_8005a43c:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return uVar2;
}

