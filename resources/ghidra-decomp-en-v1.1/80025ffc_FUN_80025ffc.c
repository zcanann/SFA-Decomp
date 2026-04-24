// Function: FUN_80025ffc
// Entry: 80025ffc
// Size: 976 bytes

/* WARNING: Removing unreachable block (ram,0x800263ac) */
/* WARNING: Removing unreachable block (ram,0x800263a4) */
/* WARNING: Removing unreachable block (ram,0x80026014) */
/* WARNING: Removing unreachable block (ram,0x8002600c) */

void FUN_80025ffc(void)

{
  int iVar1;
  int *piVar2;
  float *pfVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int *in_r6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  double in_f30;
  double in_f31;
  double dVar12;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float afStack_f8 [3];
  float afStack_ec [3];
  float afStack_e0 [3];
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  undefined4 local_c4;
  undefined4 local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float afStack_b0 [12];
  float afStack_80 [26];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar13 = FUN_80286830();
  piVar2 = (int *)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)*(char *)(*(int *)((int)uVar13 + 0x3c) + **(int **)in_r6[1] * 0x1c);
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
  FUN_802475e4((float *)(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar4 * 0x40),afStack_80);
  iVar4 = **(int **)in_r6[1];
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
  pfVar7 = (float *)(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar4 * 0x40);
  iVar10 = 4;
  iVar1 = 0x54;
  dVar12 = (double)FLOAT_803df4b8;
  for (iVar4 = 1; iVar4 < in_r6[2] + 1; iVar4 = iVar4 + 1) {
    iVar8 = *(int *)(*(int *)in_r6[1] + iVar10);
    iVar9 = (iVar4 + -1) * 0x54;
    FUN_80247bf8(afStack_80,(float *)(*in_r6 + iVar9 + 0x18),&local_d4);
    iVar6 = *in_r6;
    pfVar3 = (float *)(iVar6 + iVar1);
    local_bc = (FLOAT_803ddb50 + *pfVar3 + pfVar3[3]) - FLOAT_803dda58;
    local_b8 = pfVar3[1] + pfVar3[4];
    local_b4 = (FLOAT_803ddb4c + pfVar3[2] + pfVar3[5]) - FLOAT_803dda5c;
    local_c8 = *(float *)(iVar6 + iVar1 + -0x3c);
    local_c4 = *(undefined4 *)(iVar6 + iVar1 + -0x38);
    local_c0 = *(undefined4 *)(iVar6 + iVar1 + -0x34);
    FUN_80247e94(&local_c8,(float *)(iVar6 + iVar1 + 0x18),&local_c8);
    FUN_80247bf8(afStack_80,&local_c8,&local_c8);
    FUN_80247eb8(&local_bc,&local_d4,afStack_ec);
    FUN_80247ef8(afStack_ec,afStack_ec);
    FUN_80247eb8(&local_c8,&local_d4,afStack_e0);
    FUN_80247ef8(afStack_e0,afStack_e0);
    dVar11 = FUN_80247f90(afStack_e0,afStack_ec);
    if ((dVar11 < dVar12) && ((double)FLOAT_803df4bc < dVar11)) {
      if (((double)FLOAT_803df498 <= dVar11) || (dVar11 <= (double)FLOAT_803df4c0)) {
        FUN_802475b8(pfVar7);
      }
      else {
        FUN_80247fb0(afStack_e0,afStack_ec,afStack_f8);
        FUN_802476e4(afStack_80,afStack_b0);
        FUN_80247cd8(afStack_b0,afStack_f8,afStack_f8);
        dVar11 = (double)FUN_80292804();
        FUN_80247944(dVar11,pfVar7,afStack_f8);
      }
    }
    FUN_80247618(afStack_80,pfVar7,pfVar7);
    pfVar7[3] = local_d4;
    pfVar7[7] = local_d0;
    pfVar7[0xb] = local_cc;
    FUN_802475e4(pfVar7,afStack_80);
    iVar6 = *in_r6;
    local_c8 = *(float *)(iVar6 + iVar1 + 0x18);
    local_c4 = *(undefined4 *)(iVar6 + iVar1 + 0x1c);
    local_c0 = *(undefined4 *)(iVar6 + iVar1 + 0x20);
    FUN_80247bf8(pfVar7,&local_c8,&local_c8);
    FUN_802475e4(pfVar7,(float *)(*in_r6 + iVar9 + 0x24));
    if (iVar4 < in_r6[2]) {
      uVar5 = (uint)*(byte *)(*piVar2 + 0xf3);
      if (uVar5 == 0) {
        iVar6 = 1;
      }
      else {
        iVar6 = uVar5 + *(byte *)(*piVar2 + 0xf4);
      }
      if (iVar6 <= iVar8) {
        iVar8 = 0;
      }
      pfVar7 = (float *)(piVar2[(*(ushort *)(piVar2 + 6) & 1) + 3] + iVar8 * 0x40);
    }
    iVar10 = iVar10 + 4;
    iVar1 = iVar1 + 0x54;
  }
  FUN_8028687c();
  return;
}

