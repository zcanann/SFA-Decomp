// Function: FUN_80192974
// Entry: 80192974
// Size: 972 bytes

/* WARNING: Removing unreachable block (ram,0x80192d20) */
/* WARNING: Removing unreachable block (ram,0x80192d18) */
/* WARNING: Removing unreachable block (ram,0x80192d10) */
/* WARNING: Removing unreachable block (ram,0x80192d08) */
/* WARNING: Removing unreachable block (ram,0x80192d00) */
/* WARNING: Removing unreachable block (ram,0x801929a4) */
/* WARNING: Removing unreachable block (ram,0x8019299c) */
/* WARNING: Removing unreachable block (ram,0x80192994) */
/* WARNING: Removing unreachable block (ram,0x8019298c) */
/* WARNING: Removing unreachable block (ram,0x80192984) */

void FUN_80192974(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  short sVar5;
  int iVar6;
  int iVar7;
  short sVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  double dVar14;
  
  iVar4 = FUN_8028682c();
  DAT_803de774 = FUN_80023d8c(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 4,0xffffff);
  DAT_803de76c = FUN_80023d8c(*(int *)(iVar4 + 0x1c) * *(int *)(iVar4 + 0x1c) * 3,0xffffff);
  fVar3 = FLOAT_803e4bdc;
  *(float *)(iVar4 + 0x28) = FLOAT_803e4bdc;
  *(float *)(iVar4 + 0x24) = fVar3;
  iVar12 = 0;
  for (iVar11 = 0; fVar3 = FLOAT_803e4bdc, iVar11 < *(int *)(iVar4 + 0x1c); iVar11 = iVar11 + 1) {
    iVar7 = iVar12;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x1c); iVar10 = iVar10 + 1) {
      dVar13 = (double)FUN_802945e0();
      dVar14 = (double)(float)((double)*(float *)(iVar4 + 0x14) * dVar13);
      dVar13 = (double)FUN_802945e0();
      *(float *)(DAT_803de774 + iVar7) = (float)((double)*(float *)(iVar4 + 0x10) * dVar13 + dVar14)
      ;
      if (*(float *)(DAT_803de774 + iVar7) < *(float *)(iVar4 + 0x24)) {
        *(float *)(iVar4 + 0x24) = *(float *)(DAT_803de774 + iVar7);
      }
      if (*(float *)(iVar4 + 0x28) < *(float *)(DAT_803de774 + iVar7)) {
        *(float *)(iVar4 + 0x28) = *(float *)(DAT_803de774 + iVar7);
      }
      iVar7 = iVar7 + 4;
      iVar12 = iVar12 + 4;
    }
  }
  fVar1 = *(float *)(iVar4 + 0x24);
  iVar11 = 0;
  iVar12 = 0;
  for (iVar7 = 0; iVar7 < *(int *)(iVar4 + 0x1c); iVar7 = iVar7 + 1) {
    iVar10 = iVar11;
    iVar6 = iVar12;
    for (iVar9 = 0; iVar9 < *(int *)(iVar4 + 0x1c); iVar9 = iVar9 + 1) {
      if (fVar3 <= *(float *)(DAT_803de774 + iVar11)) {
        *(undefined *)(DAT_803de76c + iVar12) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 1) = 0xff;
        *(undefined *)(DAT_803de76c + iVar12 + 2) = 0xff;
      }
      else {
        fVar2 = (*(float *)(DAT_803de774 + iVar11) - *(float *)(iVar4 + 0x24)) / -fVar1;
        *(char *)(DAT_803de76c + iVar12) = (char)(int)(FLOAT_803e4bec * fVar2 + FLOAT_803e4be8);
        *(char *)(DAT_803de76c + iVar12 + 1) = (char)(int)(FLOAT_803e4bf4 * fVar2 + FLOAT_803e4bf0);
        *(char *)(DAT_803de76c + iVar12 + 2) = (char)(int)(FLOAT_803e4bfc * fVar2 + FLOAT_803e4bf8);
      }
      iVar11 = iVar11 + 4;
      iVar12 = iVar12 + 3;
      iVar10 = iVar10 + 4;
      iVar6 = iVar6 + 3;
    }
    iVar11 = iVar10;
    iVar12 = iVar6;
  }
  DAT_803de770 = FUN_80023d8c(*(int *)(iVar4 + 0x20) * *(int *)(iVar4 + 0x20) * 4,0xffffff);
  sVar8 = 0;
  iVar11 = 0;
  for (iVar12 = 0; iVar12 < *(int *)(iVar4 + 0x20); iVar12 = iVar12 + 1) {
    sVar5 = 0;
    iVar7 = iVar11;
    for (iVar10 = 0; iVar10 < *(int *)(iVar4 + 0x20); iVar10 = iVar10 + 1) {
      *(short *)(DAT_803de770 + iVar11) = sVar8;
      *(short *)(DAT_803de770 + iVar11 + 2) = sVar5;
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 4;
      sVar5 = sVar5 + 10;
    }
    sVar8 = sVar8 + 10;
    iVar11 = iVar7;
  }
  FUN_80286878();
  return;
}

