// Function: FUN_8022a2e0
// Entry: 8022a2e0
// Size: 852 bytes

/* WARNING: Removing unreachable block (ram,0x8022a344) */
/* WARNING: Removing unreachable block (ram,0x8022a614) */

void FUN_8022a2e0(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  undefined2 uVar6;
  int iVar7;
  float *pfVar8;
  undefined4 uVar9;
  undefined8 in_f31;
  double dVar10;
  double local_38;
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar4 = FUN_802860dc();
  pfVar8 = *(float **)(iVar4 + 0xb8);
  iVar7 = *(int *)(iVar4 + 0x4c);
  iVar5 = FUN_8001ffb4(0x338);
  if (iVar5 != 0) {
    *(undefined4 *)(iVar4 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
    *(undefined *)((int)pfVar8 + 6) = 3;
  }
  bVar1 = *(byte *)((int)pfVar8 + 6);
  if (bVar1 == 2) {
    *(undefined *)(iVar4 + 0x36) = 0;
    FUN_80035f00(iVar4);
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 3;
  }
  else {
    if (bVar1 < 2) {
      if (bVar1 != 0) {
        *pfVar8 = *pfVar8 + FLOAT_803db414;
        fVar2 = FLOAT_803e6ea0;
        if (FLOAT_803e6ea0 < *pfVar8) {
          *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 3;
          *pfVar8 = fVar2;
          *(float *)(iVar4 + 0x28) = FLOAT_803e6ea4 * FLOAT_803db414 + *(float *)(iVar4 + 0x28);
        }
        *(short *)(pfVar8 + 1) = (short)(int)(FLOAT_803e6ea8 * (*pfVar8 / FLOAT_803e6ea0));
        uVar6 = FUN_800221a0(-(int)*(short *)(pfVar8 + 1));
        *(undefined2 *)(iVar4 + 2) = uVar6;
        uVar6 = FUN_800221a0(-(int)*(short *)(pfVar8 + 1));
        *(undefined2 *)(iVar4 + 4) = uVar6;
        *(float *)(iVar4 + 0x10) =
             *(float *)(iVar4 + 0x28) * FLOAT_803db414 + *(float *)(iVar4 + 0x10);
        fVar2 = *(float *)(iVar7 + 0xc) - *(float *)(iVar4 + 0x10);
        fVar3 = FLOAT_803e6eb0;
        if ((FLOAT_803e6eac <= fVar2) && (fVar3 = FLOAT_803e6e9c, fVar2 <= FLOAT_803e6eb4)) {
          fVar2 = FLOAT_803e6e98 - (fVar2 - FLOAT_803e6eac) / FLOAT_803e6eb8;
          fVar3 = FLOAT_803e6e98;
          if ((fVar2 <= FLOAT_803e6e98) && (fVar3 = fVar2, fVar2 < FLOAT_803e6e9c)) {
            fVar3 = FLOAT_803e6e9c;
          }
          fVar3 = fVar3 * FLOAT_803e6eb0;
        }
        *(char *)(iVar4 + 0x36) = (char)(int)fVar3;
        if (*(char *)(iVar4 + 0x36) == '\0') {
          *(undefined *)((int)pfVar8 + 6) = 2;
        }
        goto LAB_8022a5b4;
      }
    }
    else if (bVar1 < 4) {
      local_38 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x36));
      fVar2 = FLOAT_803e6ebc * FLOAT_803db414 + (float)(local_38 - DOUBLE_803e6ec0);
      if (FLOAT_803e6eb0 < fVar2) {
        fVar2 = FLOAT_803e6eb0;
      }
      *(char *)(iVar4 + 0x36) = (char)(int)fVar2;
      FUN_80035f20(iVar4);
      goto LAB_8022a5b4;
    }
    if ((*(byte *)((int)pfVar8 + 7) & 4) == 0) {
      iVar5 = FUN_8001ffb4(0x265);
      if (iVar5 != 0) {
        *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 4;
      }
    }
    else if ('\0' < *(char *)(*(int *)(iVar4 + 0x58) + 0x10f)) {
      iVar7 = 0;
      dVar10 = (double)FLOAT_803e6e9c;
      for (iVar5 = 0; iVar5 < *(char *)(*(int *)(iVar4 + 0x58) + 0x10f); iVar5 = iVar5 + 1) {
        if (*(short *)(*(int *)(*(int *)(iVar4 + 0x58) + iVar7 + 0x100) + 0x44) == 1) {
          FUN_8000bb18(iVar4,0xc6);
          *(undefined *)((int)pfVar8 + 6) = 1;
          *pfVar8 = (float)dVar10;
          *(float *)(iVar4 + 0x28) = (float)dVar10;
        }
        iVar7 = iVar7 + 4;
      }
    }
  }
LAB_8022a5b4:
  iVar7 = *(int *)(iVar4 + 0x4c);
  iVar5 = FUN_80065640();
  if (iVar5 != 0) {
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) | 2;
  }
  if (((*(byte *)((int)pfVar8 + 7) & 2) != 0) && (iVar5 = FUN_80065640(), iVar5 == 0)) {
    FUN_80065574((int)*(short *)(iVar7 + 0x1a),*(undefined4 *)(iVar4 + 0x30),
                 *(byte *)((int)pfVar8 + 7) & 1);
    *(byte *)((int)pfVar8 + 7) = *(byte *)((int)pfVar8 + 7) & 0xfd;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  FUN_80286128();
  return;
}

