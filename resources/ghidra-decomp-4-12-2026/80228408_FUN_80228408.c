// Function: FUN_80228408
// Entry: 80228408
// Size: 840 bytes

/* WARNING: Removing unreachable block (ram,0x8022872c) */
/* WARNING: Removing unreachable block (ram,0x80228418) */

void FUN_80228408(uint param_1)

{
  char cVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint *puVar6;
  byte bVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  char *pcVar12;
  int iVar13;
  double dVar14;
  
  iVar13 = *(int *)(param_1 + 0x4c);
  pcVar12 = *(char **)(param_1 + 0xb8);
  if ((*(short *)(iVar13 + 0x20) < 1) ||
     (uVar4 = FUN_80020078((int)*(short *)(iVar13 + 0x20)), uVar4 != 0)) {
    cVar1 = *pcVar12;
    *pcVar12 = cVar1 + -1;
    if ((char)(cVar1 + -1) < '\0') {
      *pcVar12 = '\0';
    }
    dVar14 = DOUBLE_803e7aa0;
    if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
      iVar8 = 0;
      for (iVar11 = 0; iVar11 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar11 = iVar11 + 1) {
        iVar10 = *(int *)(*(int *)(param_1 + 0x58) + iVar8 + 0x100);
        if ((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1d)) - dVar14) <
            *(float *)(iVar10 + 0x10) - *(float *)(param_1 + 0x10)) {
          iVar9 = *(int *)(param_1 + 0xb8);
          uVar4 = 0;
          while( true ) {
            uVar3 = uVar4 & 0xff;
            iVar5 = uVar3 * 4 + 4;
            if ((*(int *)(iVar9 + iVar5) == 0) && (uVar3 != 9)) break;
            uVar4 = uVar4 + 1;
          }
          *(int *)(iVar9 + iVar5) = iVar10;
          iVar9 = iVar9 + uVar3 * 8;
          *(undefined4 *)(iVar9 + 0x2c) = *(undefined4 *)(iVar10 + 0xc);
          *(undefined4 *)(iVar9 + 0x30) = *(undefined4 *)(iVar10 + 0x14);
        }
        iVar8 = iVar8 + 4;
      }
    }
    iVar8 = *(int *)(param_1 + 0xb8);
    bVar2 = false;
    for (bVar7 = 0; bVar7 < 10; bVar7 = bVar7 + 1) {
      iVar10 = (uint)bVar7 * 4 + 4;
      iVar11 = *(int *)(iVar8 + iVar10);
      if (iVar11 != 0) {
        iVar9 = iVar8 + (uint)bVar7 * 8;
        if ((*(float *)(iVar9 + 0x2c) == *(float *)(iVar11 + 0xc)) &&
           (*(float *)(iVar9 + 0x30) == *(float *)(iVar11 + 0x14))) {
          bVar2 = true;
        }
        else {
          *(undefined4 *)(iVar8 + iVar10) = 0;
        }
      }
    }
    if (bVar2) {
      *pcVar12 = '\x05';
    }
    dVar14 = (double)(*(float *)(iVar13 + 0xc) -
                     (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar13 + 0x1c)) -
                            DOUBLE_803e7aa0));
    cVar1 = pcVar12[1];
    if (cVar1 == '\x02') {
      uVar4 = FUN_80020078((int)*(short *)(iVar13 + 0x1a));
      if (uVar4 == 0) {
        FUN_8000bb38(param_1,199);
        pcVar12[1] = '\x01';
      }
    }
    else if (cVar1 < '\x02') {
      if (cVar1 == '\0') {
        if ((*pcVar12 != '\0') && (dVar14 <= (double)*(float *)(param_1 + 0x10))) {
          FUN_8000bb38(param_1,199);
          pcVar12[1] = '\x03';
        }
      }
      else if (-1 < cVar1) {
        *(float *)(param_1 + 0x10) = FLOAT_803e7a9c * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
        if (*(float *)(iVar13 + 0xc) < *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = *(float *)(iVar13 + 0xc);
          pcVar12[1] = '\0';
        }
      }
    }
    else if ((cVar1 < '\x04') &&
            (*(float *)(param_1 + 0x10) =
                  -(FLOAT_803e7a9c * FLOAT_803dc074 - *(float *)(param_1 + 0x10)),
            (double)*(float *)(param_1 + 0x10) < dVar14)) {
      FUN_800201ac((int)*(short *)(iVar13 + 0x1a),1);
      pcVar12[1] = '\x02';
      *(float *)(param_1 + 0x10) = (float)dVar14;
    }
    puVar6 = (uint *)FUN_800395a4(param_1,0);
    if (puVar6 != (uint *)0x0) {
      *puVar6 = (uint)(pcVar12[1] == '\x02');
      *puVar6 = *puVar6 << 8;
    }
  }
  else {
    FUN_80137cd0();
  }
  return;
}

