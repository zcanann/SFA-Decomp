// Function: FUN_8022a9a4
// Entry: 8022a9a4
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x8022acd8) */
/* WARNING: Removing unreachable block (ram,0x8022aa08) */
/* WARNING: Removing unreachable block (ram,0x8022a9b4) */

void FUN_8022a9a4(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  double dVar9;
  undefined8 local_38;
  
  uVar4 = FUN_80286840();
  pfVar8 = *(float **)(uVar4 + 0xb8);
  iVar6 = *(int *)(uVar4 + 0x4c);
  uVar5 = FUN_80020078(0x338);
  if (uVar5 != 0) {
    *(undefined4 *)(uVar4 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined *)((int)pfVar8 + 6) = 3;
  }
  bVar1 = *(byte *)((int)pfVar8 + 6);
  if (bVar1 == 2) {
    *(undefined *)(uVar4 + 0x36) = 0;
    FUN_80035ff8(uVar4);
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 3;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
        *pfVar8 = *pfVar8 + FLOAT_803dc074;
        fVar2 = FLOAT_803e7b38;
        if (FLOAT_803e7b38 < *pfVar8) {
          *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 3;
          *pfVar8 = fVar2;
          *(float *)(uVar4 + 0x28) = FLOAT_803e7b3c * FLOAT_803dc074 + *(float *)(uVar4 + 0x28);
        }
        *(short *)(pfVar8 + 1) = (short)(int)(FLOAT_803e7b40 * (*pfVar8 / FLOAT_803e7b38));
        uVar5 = FUN_80022264(-(int)*(short *)(pfVar8 + 1),(int)*(short *)(pfVar8 + 1));
        *(short *)(uVar4 + 2) = (short)uVar5;
        uVar5 = FUN_80022264(-(int)*(short *)(pfVar8 + 1),(int)*(short *)(pfVar8 + 1));
        *(short *)(uVar4 + 4) = (short)uVar5;
        *(float *)(uVar4 + 0x10) =
             *(float *)(uVar4 + 0x28) * FLOAT_803dc074 + *(float *)(uVar4 + 0x10);
        fVar2 = *(float *)(iVar6 + 0xc) - *(float *)(uVar4 + 0x10);
        fVar3 = FLOAT_803e7b48;
        if ((FLOAT_803e7b44 <= fVar2) && (fVar3 = FLOAT_803e7b34, fVar2 <= FLOAT_803e7b4c)) {
          fVar2 = FLOAT_803e7b30 - (fVar2 - FLOAT_803e7b44) / FLOAT_803e7b50;
          fVar3 = FLOAT_803e7b30;
          if ((fVar2 <= FLOAT_803e7b30) && (fVar3 = fVar2, fVar2 < FLOAT_803e7b34)) {
            fVar3 = FLOAT_803e7b34;
          }
          fVar3 = fVar3 * FLOAT_803e7b48;
        }
        *(char *)(uVar4 + 0x36) = (char)(int)fVar3;
        if (*(char *)(uVar4 + 0x36) == '\0') {
          *(undefined *)((int)pfVar8 + 6) = 2;
        }
        goto LAB_8022ac78;
      }
    }
    else if (bVar1 < 4) {
      local_38 = (double)CONCAT44(0x43300000,(uint)*(byte *)(uVar4 + 0x36));
      fVar2 = FLOAT_803e7b54 * FLOAT_803dc074 + (float)(local_38 - DOUBLE_803e7b58);
      if (FLOAT_803e7b48 < fVar2) {
        fVar2 = FLOAT_803e7b48;
      }
      *(char *)(uVar4 + 0x36) = (char)(int)fVar2;
      FUN_80036018(uVar4);
      goto LAB_8022ac78;
    }
    if ((*(byte *)((int)pfVar8 + 7) & 4) == 0) {
      uVar5 = FUN_80020078(0x265);
      if (uVar5 != 0) {
        *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 4;
      }
    }
    else if ('\0' < *(char *)(*(int *)(uVar4 + 0x58) + 0x10f)) {
      iVar7 = 0;
      dVar9 = (double)FLOAT_803e7b34;
      for (iVar6 = 0; iVar6 < *(char *)(*(int *)(uVar4 + 0x58) + 0x10f); iVar6 = iVar6 + 1) {
        if (*(short *)(*(int *)(*(int *)(uVar4 + 0x58) + iVar7 + 0x100) + 0x44) == 1) {
          FUN_8000bb38(uVar4,0xc6);
          *(undefined *)((int)pfVar8 + 6) = 1;
          *pfVar8 = (float)dVar9;
          *(float *)(uVar4 + 0x28) = (float)dVar9;
        }
        iVar7 = iVar7 + 4;
      }
    }
  }
LAB_8022ac78:
  iVar7 = *(int *)(uVar4 + 0x4c);
  iVar6 = FUN_800657bc();
  if (iVar6 != 0) {
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 2;
  }
  if (((*(byte *)((int)pfVar8 + 7) & 2) != 0) && (iVar6 = FUN_800657bc(), iVar6 == 0)) {
    FUN_800656f0((int)*(short *)(iVar7 + 0x1a),*(int *)(uVar4 + 0x30),*(byte *)((int)pfVar8 + 7) & 1
                );
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) & 0xfd;
  }
  FUN_8028688c();
  return;
}

