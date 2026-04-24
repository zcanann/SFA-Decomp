// Function: FUN_801f1ca4
// Entry: 801f1ca4
// Size: 1104 bytes

/* WARNING: Removing unreachable block (ram,0x801f20d4) */
/* WARNING: Removing unreachable block (ram,0x801f1cb4) */

void FUN_801f1ca4(void)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  char cVar6;
  uint uVar5;
  int iVar7;
  int iVar8;
  char *pcVar9;
  int iVar10;
  bool bVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  
  uVar3 = FUN_8028683c();
  iVar4 = FUN_8002bac4();
  iVar10 = *(int *)(uVar3 + 0x4c);
  pcVar9 = *(char **)(uVar3 + 0xb8);
  dVar13 = (double)FUN_800217c8((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18));
  dVar12 = (double)FLOAT_803e69f4;
  *pcVar9 = *pcVar9 + -1;
  if (*pcVar9 < '\0') {
    *pcVar9 = '\0';
    pcVar9[1] = '\0';
  }
  iVar4 = 0;
  pcVar9[6] = pcVar9[6] & 0x7f;
  if ((*(int *)(uVar3 + 0x58) == 0) || (*(char *)(*(int *)(uVar3 + 0x58) + 0x10f) < '\x01')) {
    if ((*(char *)(uVar3 + 0xac) == '\v') &&
       (((cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x03' &&
         (iVar4 = FUN_8002ba84(), iVar4 != 0)) &&
        (dVar14 = (double)FUN_800217c8((float *)(uVar3 + 0x18),(float *)(iVar4 + 0x18)),
        dVar14 < (double)FLOAT_803e69fc)))) {
      *pcVar9 = '\x05';
    }
  }
  else {
    *(short *)(pcVar9 + 2) = *(short *)(iVar10 + 0x1e) * 0x3c;
    dVar14 = (double)FLOAT_803e69f8;
    for (iVar8 = 0; iVar8 < *(char *)(*(int *)(uVar3 + 0x58) + 0x10f); iVar8 = iVar8 + 1) {
      iVar7 = *(int *)(*(int *)(uVar3 + 0x58) + iVar4 + 0x100);
      if (*(short *)(iVar7 + 0x46) == 0x6d) {
        pcVar9[6] = pcVar9[6] & 0x7fU | 0x80;
      }
      if (dVar14 < (double)(*(float *)(iVar7 + 0x10) - *(float *)(uVar3 + 0x10))) {
        *pcVar9 = '\x05';
      }
      if (((pcVar9[1] == '\0') && (iVar7 != 0)) && (*(short *)(iVar7 + 0x46) == 0x146)) {
        if (dVar13 <= dVar12) {
          FUN_8000bb38(uVar3,0x7e);
        }
        pcVar9[1] = '\x01';
      }
      iVar4 = iVar4 + 4;
    }
  }
  if (((*(char *)(uVar3 + 0xac) == '\v') &&
      (cVar6 = (**(code **)(*DAT_803dd72c + 0x40))(), cVar6 == '\x01')) && (dVar13 <= dVar12)) {
    if (*pcVar9 == '\0') {
      uVar5 = FUN_80020078(0x905);
      if (uVar5 != 0) {
        FUN_800201ac(0x905,0);
      }
    }
    else {
      fVar1 = *(float *)(iVar10 + 0xc) - *(float *)(uVar3 + 0x10);
      if (((fVar1 <= FLOAT_803e6a00) || (FLOAT_803e6a04 <= fVar1)) ||
         (uVar5 = FUN_80020078((int)*(short *)(pcVar9 + 4)), uVar5 != 0)) {
        uVar5 = FUN_80020078(0x905);
        if (uVar5 != 0) {
          FUN_800201ac(0x905,0);
        }
      }
      else {
        FUN_800201ac(0x905,1);
      }
    }
  }
  bVar11 = false;
  if (*pcVar9 == '\0') {
    if (*(short *)(pcVar9 + 2) == 0) {
      *(float *)(uVar3 + 0x10) = FLOAT_803e6a0c * FLOAT_803dc074 + *(float *)(uVar3 + 0x10);
      bVar11 = *(float *)(uVar3 + 0x10) <= *(float *)(iVar10 + 0xc);
      if (!bVar11) {
        *(float *)(uVar3 + 0x10) = *(float *)(iVar10 + 0xc);
      }
      FUN_800201ac((int)*(short *)(iVar10 + 0x1c),0);
      if (((int)*(short *)(pcVar9 + 4) != 0xffffffff) && (((byte)pcVar9[6] >> 6 & 1) == 0)) {
        FUN_800201ac((int)*(short *)(pcVar9 + 4),0);
      }
    }
  }
  else {
    fVar2 = *(float *)(iVar10 + 0xc) - FLOAT_803e6a04;
    fVar1 = *(float *)(uVar3 + 0x10);
    if (fVar2 <= fVar1) {
      *(float *)(uVar3 + 0x10) = -(FLOAT_803e6a0c * FLOAT_803dc074 - fVar1);
      if (fVar2 <= *(float *)(uVar3 + 0x10)) {
        bVar11 = true;
      }
      else {
        *(float *)(uVar3 + 0x10) = fVar2;
        FUN_800201ac((int)*(short *)(iVar10 + 0x1c),1);
        if ((int)*(short *)(pcVar9 + 4) != 0xffffffff) {
          FUN_800201ac((int)*(short *)(pcVar9 + 4),1);
          if (pcVar9[6] < '\0') {
            pcVar9[6] = pcVar9[6] & 0xbfU | 0x40;
          }
        }
      }
    }
    else {
      *(float *)(uVar3 + 0x10) = FLOAT_803e6a08 * FLOAT_803dc074 + fVar1;
      if (fVar2 < *(float *)(uVar3 + 0x10)) {
        *(float *)(uVar3 + 0x10) = fVar2;
      }
      FUN_800201ac((int)*(short *)(iVar10 + 0x1c),1);
      if (pcVar9[6] < '\0') {
        FUN_800201ac((int)*(short *)(pcVar9 + 4),1);
      }
    }
  }
  if (bVar11) {
    FUN_8000bb38(uVar3,0x7f);
  }
  else {
    FUN_8000b7dc(uVar3,8);
  }
  if ((*(short *)(pcVar9 + 2) != 0) &&
     (*(ushort *)(pcVar9 + 2) = *(short *)(pcVar9 + 2) - (ushort)DAT_803dc070,
     *(short *)(pcVar9 + 2) < 0)) {
    pcVar9[2] = '\0';
    pcVar9[3] = '\0';
  }
  FUN_80286888();
  return;
}

