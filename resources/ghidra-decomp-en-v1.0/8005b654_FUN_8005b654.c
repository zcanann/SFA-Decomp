// Function: FUN_8005b654
// Entry: 8005b654
// Size: 1132 bytes

void FUN_8005b654(void)

{
  float fVar1;
  short sVar2;
  char *pcVar3;
  int *piVar4;
  int iVar5;
  char cVar7;
  int iVar6;
  int iVar8;
  uint uVar9;
  undefined4 uVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  float local_48;
  undefined auStack68 [4];
  undefined auStack64 [4];
  int local_3c;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  
  pcVar3 = (char *)FUN_802860d4();
  FUN_8006c91c();
  piVar4 = (int *)FUN_8002e0fc(0,0);
  iVar5 = FUN_8002e190(&local_3c);
  for (uVar13 = 0; (int)uVar13 < local_3c; uVar13 = uVar13 + 1) {
    iVar14 = *piVar4;
    *(ushort *)(iVar14 + 0xb0) = *(ushort *)(iVar14 + 0xb0) & 0xf7ff;
    iVar6 = iVar14;
    for (iVar11 = 0; iVar11 < (int)(uint)*(byte *)(iVar14 + 0xeb); iVar11 = iVar11 + 1) {
      iVar8 = *(int *)(iVar6 + 200);
      if (iVar8 != 0) {
        *(ushort *)(iVar8 + 0xb0) = *(ushort *)(iVar8 + 0xb0) & 0xf7ff;
      }
      iVar6 = iVar6 + 4;
    }
    if (iVar5 <= (int)uVar13) {
      cVar7 = FUN_8005a194(iVar14);
      *pcVar3 = cVar7;
      if ((*pcVar3 == '\0') && ((*(uint *)(*(int *)(iVar14 + 0x50) + 0x44) & 0x200000) == 0)) {
        iVar6 = *(int *)(iVar14 + 0x54);
        if ((iVar6 != 0) && ((*(byte *)(iVar6 + 0x62) & 0x30) != 0)) {
          *(undefined *)(iVar6 + 0xaf) = 2;
        }
      }
      else {
        if ((*(uint *)(*(int *)(iVar14 + 0x50) + 0x44) & 0x80000) == 0) {
          if (*(int *)(iVar14 + 0x30) == 0) {
            FUN_8000ef48((double)(*(float *)(iVar14 + 0xc) - FLOAT_803dcdd8),
                         (double)*(float *)(iVar14 + 0x10),
                         (double)(*(float *)(iVar14 + 0x14) - FLOAT_803dcddc),auStack64,auStack68,
                         &local_48,iVar14 + 0xa4);
          }
          else {
            FUN_8000ef48((double)*(float *)(iVar14 + 0x18),(double)*(float *)(iVar14 + 0x1c),
                         (double)*(float *)(iVar14 + 0x20),auStack64,auStack68,&local_48,
                         iVar14 + 0xa4);
          }
          fVar1 = FLOAT_803dec0c * (FLOAT_803debdc + local_48);
        }
        else {
          uStack52 = (uint)*(byte *)(*(int *)(iVar14 + 0x50) + 0x74) * 100 ^ 0x80000000;
          local_38 = 0x43300000;
          *(float *)(iVar14 + 0xa4) =
               (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803debc0);
          fVar1 = *(float *)(iVar14 + 0xa4);
        }
        local_30 = (longlong)(int)fVar1;
        if ((((*(ushort *)(iVar14 + 6) & 0x4000) == 0) && (*(int *)(iVar14 + 100) != 0)) &&
           ((*(uint *)(*(int *)(iVar14 + 100) + 0x30) & 4) != 0)) {
          sVar2 = *(short *)(*(int *)(iVar14 + 0x50) + 0x48);
          if ((sVar2 == 2) || (sVar2 == 1)) {
            FUN_8006c384(iVar14);
          }
          else if (sVar2 == 4) {
            FUN_8006b558(iVar14);
          }
        }
        if (DAT_803dceae < 1000) {
          iVar6 = FUN_8002b588(iVar14);
          if (((*(char *)(iVar14 + 0x37) == -1) && ((*(ushort *)(iVar14 + 6) & 0x80) == 0)) &&
             ((uVar9 = *(uint *)(*(int *)(iVar14 + 0x50) + 0x44), (uVar9 & 0x40000) == 0 &&
              (*(int *)(iVar6 + 0x58) == 0)))) {
            uVar12 = 0x80000000;
            if (((uVar9 & 0x800000) != 0) && ((*(byte *)(iVar14 + 0xe5) & 2) == 0)) {
              uVar12 = ((int)*(short *)(iVar14 + 0x46) & 0x3ffU) << 0x14 | 0xc0000000;
            }
            (&DAT_803868d8)[DAT_803dceae] =
                 uVar13 & 0x3ff | (1000 - ((int)fVar1 & 0xffffU) & 0x3ff) << 10 | uVar12;
            DAT_803dceae = DAT_803dceae + 1;
            if ((((*(byte *)(*(int *)(iVar14 + 0x50) + 0x5f) & 0x20) != 0) &&
                ((*(ushort *)(iVar14 + 0xb0) & 0x400) == 0)) &&
               ((*(ushort *)(iVar14 + 6) & 0x4000) == 0)) {
              FUN_8005d150(iVar14,7,0x50);
              (&DAT_8037e0cc)[DAT_803dce30 * 4] = 1;
              DAT_803dce30 = DAT_803dce30 + 1;
            }
          }
          else {
            if (((*(uint *)(*(int *)(iVar14 + 0x50) + 0x44) & 0x800) == 0) &&
               ((*(byte *)(*(int *)(iVar14 + 0x50) + 0x5f) & 0x10) == 0)) {
              uVar10 = 7;
            }
            else {
              uVar10 = 0x1f;
            }
            FUN_8005d150(iVar14,uVar10,0);
            (&DAT_8037e0cc)[DAT_803dce30 * 4] = 0;
            DAT_803dce30 = DAT_803dce30 + 1;
            if (((*(byte *)(*(int *)(iVar14 + 0x50) + 0x5f) & 0x20) != 0) &&
               ((*(ushort *)(iVar14 + 6) & 0x4000) == 0)) {
              FUN_8005d150(iVar14,7,0x50);
              (&DAT_8037e0cc)[DAT_803dce30 * 4] = 1;
              DAT_803dce30 = DAT_803dce30 + 1;
            }
          }
        }
      }
    }
    piVar4 = piVar4 + 1;
    pcVar3 = pcVar3 + 1;
  }
  if (1 < DAT_803dceae) {
    FUN_8005b56c(&DAT_803868d8);
  }
  FUN_8006b960(0,0,0);
  FUN_80286120();
  return;
}

