// Function: FUN_800274c8
// Entry: 800274c8
// Size: 1040 bytes

void FUN_800274c8(void)

{
  byte bVar1;
  float fVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  uint *puVar7;
  float *pfVar8;
  short *psVar9;
  short *psVar10;
  undefined4 in_r9;
  int in_r10;
  int iVar11;
  uint *puVar12;
  uint *puVar13;
  int iVar14;
  short local_48 [2];
  uint local_44 [7];
  longlong local_28;
  
  piVar3 = (int *)FUN_80286838();
  local_44[3] = DAT_802c2268;
  local_44[4] = DAT_802c226c;
  local_44[5] = DAT_802c2270;
  local_44[0] = DAT_802c2274;
  local_44[1] = DAT_802c2278;
  local_44[2] = DAT_802c227c;
  iVar11 = *piVar3;
  if (*(int *)(iVar11 + 0xdc) != 0) {
    local_48[0] = *(short *)(iVar11 + 0xe4) + 1;
    iVar4 = 0;
    puVar12 = local_44;
    puVar13 = local_44 + 3;
    iVar14 = 3;
    puVar6 = puVar12;
    puVar7 = puVar13;
    do {
      pfVar8 = (float *)(piVar3[10] + iVar4);
      if (*pfVar8 != pfVar8[1]) {
        *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) & 0xf3;
        *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) | 4;
      }
      bVar1 = *(byte *)((int)pfVar8 + 0xe);
      *puVar6 = bVar1 & 0xc;
      if (((*(char *)(pfVar8 + 3) != -1) || (*(char *)((int)pfVar8 + 0xd) != -1)) ||
         ((bVar1 & 0xc) != 0)) {
        *puVar7 = 1;
      }
      if ((*puVar6 & 4) == 0) {
        if ((*puVar6 & 8) != 0) {
          *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) & 0xf7;
        }
      }
      else {
        *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) & 0xfb;
        *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) | 8;
      }
      iVar4 = iVar4 + 0x10;
      puVar6 = puVar6 + 1;
      puVar7 = puVar7 + 1;
      iVar14 = iVar14 + -1;
    } while (iVar14 != 0);
    if (((local_44[3] != 0) || (local_44[4] != 0)) || (local_44[5] != 0)) {
      if (local_44[4] != 0) {
        local_44[3] = 0;
      }
      if (local_44[2] != 0) {
        local_44[0] = 1;
        local_44[1] = 1;
      }
      if ((((local_44[3] != 0) && (local_44[0] != 0)) || ((local_44[4] != 0 && (local_44[1] != 0))))
         && (local_44[5] != 0)) {
        local_44[2] = 1;
      }
      iVar4 = 0;
      iVar14 = 0;
      do {
        if ((*puVar13 != 0) && (*(int *)(iVar11 + 0xa4) != 0)) {
          *puVar12 = 1;
        }
        pfVar8 = (float *)(piVar3[10] + iVar14);
        if ((*(byte *)((int)pfVar8 + 0xe) & 2) != 0) {
          *(byte *)((int)pfVar8 + 0xe) = *(byte *)((int)pfVar8 + 0xe) & 0xfd;
          *pfVar8 = FLOAT_803df4a8;
        }
        if ((*puVar13 != 0) && (*puVar12 != 0)) {
          if (*(char *)(pfVar8 + 3) < 0) {
            psVar9 = local_48;
          }
          else {
            psVar9 = *(short **)(*(int *)(iVar11 + 0xdc) + *(char *)(pfVar8 + 3) * 4);
          }
          if (*(char *)((int)pfVar8 + 0xd) < 0) {
            psVar10 = local_48;
          }
          else {
            psVar10 = *(short **)(*(int *)(iVar11 + 0xdc) + *(char *)((int)pfVar8 + 0xd) * 4);
          }
          if (iVar4 == 2) {
            if ((local_44[3] == 0) && (local_44[4] == 0)) {
              iVar5 = *(int *)(iVar11 + 0x28);
            }
            else {
              iVar5 = piVar3[(*(ushort *)(piVar3 + 6) >> 1 & 1) + 7];
            }
          }
          else {
            iVar5 = *(int *)(iVar11 + 0x28);
          }
          fVar2 = *pfVar8;
          if (fVar2 <= FLOAT_803df498) {
            if (fVar2 < FLOAT_803df4a8) {
              if ((*(byte *)((int)pfVar8 + 0xe) & 0x20) == 0) {
                *pfVar8 = FLOAT_803df4a8;
              }
              else if (fVar2 < FLOAT_803df4c0) {
                *pfVar8 = FLOAT_803df4c0;
              }
            }
          }
          else {
            *pfVar8 = FLOAT_803df498;
          }
          fVar2 = *pfVar8;
          if (fVar2 < FLOAT_803df4a8) {
            fVar2 = fVar2 * FLOAT_803df4c0;
            fVar2 = -(fVar2 * fVar2 * fVar2 -
                     (FLOAT_803df4e8 * fVar2 + FLOAT_803df4ec * fVar2 * fVar2)) * FLOAT_803df4c0;
          }
          else {
            fVar2 = -(fVar2 * fVar2 * fVar2 -
                     (FLOAT_803df4e8 * fVar2 + FLOAT_803df4ec * fVar2 * fVar2));
          }
          local_28 = (longlong)(int)(FLOAT_803df4f0 * fVar2);
          FUN_80027048(iVar5,piVar3[(*(ushort *)(piVar3 + 6) >> 1 & 1) + 7],
                       (uint)*(ushort *)(iVar11 + 0xe4),psVar9,psVar10,(int)(FLOAT_803df4f0 * fVar2)
                       ,in_r9,in_r10);
          *(undefined *)(piVar3 + 0x18) = 1;
        }
        if (pfVar8[1] != *pfVar8) {
          pfVar8[1] = *pfVar8;
        }
        puVar13 = puVar13 + 1;
        puVar12 = puVar12 + 1;
        iVar14 = iVar14 + 0x10;
        iVar4 = iVar4 + 1;
      } while (iVar4 < 3);
    }
  }
  FUN_80286884();
  return;
}

