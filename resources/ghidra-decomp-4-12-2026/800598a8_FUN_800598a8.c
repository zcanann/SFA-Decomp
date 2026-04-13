// Function: FUN_800598a8
// Entry: 800598a8
// Size: 804 bytes

void FUN_800598a8(void)

{
  byte *pbVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  int in_r6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  short *psVar10;
  int iVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_80286834();
  iVar11 = (int)((ulonglong)uVar12 >> 0x20);
  puVar6 = (uint *)uVar12;
  bVar3 = false;
  uVar7 = 0;
  psVar10 = *(short **)(iVar11 + 0x20);
  uVar9 = (uint)*(ushort *)(iVar11 + 8);
  if (uVar9 != 0) {
    iVar8 = 0;
    if (in_r6 == 0) {
      puVar6[0x21] = 0xffffffff;
      *puVar6 = 0xffffffff;
      puVar6[1] = 0xffffffff;
      puVar6[2] = 0xffffffff;
      puVar6[3] = 0xffffffff;
      puVar6[4] = 0xffffffff;
      puVar6[5] = 0xffffffff;
      puVar6[6] = 0xffffffff;
      puVar6[7] = 0xffffffff;
      puVar6[8] = 0xffffffff;
      puVar6[9] = 0xffffffff;
      puVar6[10] = 0xffffffff;
      puVar6[0xb] = 0xffffffff;
      puVar6[0xc] = 0xffffffff;
      puVar6[0xd] = 0xffffffff;
      puVar6[0xe] = 0xffffffff;
      puVar6[0xf] = 0xffffffff;
      puVar6[0x10] = 0xffffffff;
      puVar6[0x11] = 0xffffffff;
      puVar6[0x12] = 0xffffffff;
      puVar6[0x13] = 0xffffffff;
      puVar6[0x14] = 0xffffffff;
      puVar6[0x15] = 0xffffffff;
      puVar6[0x16] = 0xffffffff;
      puVar6[0x17] = 0xffffffff;
      puVar6[0x18] = 0xffffffff;
      puVar6[0x19] = 0xffffffff;
      puVar6[0x1a] = 0xffffffff;
      puVar6[0x1b] = 0xffffffff;
      puVar6[0x1c] = 0xffffffff;
      puVar6[0x1d] = 0xffffffff;
      puVar6[0x1e] = 0xffffffff;
      puVar6[0x1f] = 0xffffffff;
    }
    for (; iVar8 < (int)uVar9; iVar8 = iVar8 + (uint)*pbVar1 * 4) {
      if (in_r6 == 0) {
        sVar2 = *psVar10;
        if ((sVar2 == 0x6e) || (sVar2 == 5)) {
          if (sVar2 == 0x6e) {
            (**(code **)(*DAT_803dd71c + 8))(psVar10);
          }
          else {
            (**(code **)(*DAT_803dd6ec + 8))(psVar10);
          }
          if (!bVar3) {
            puVar6[0x21] = (int)psVar10 - *(int *)(iVar11 + 0x20);
            bVar3 = true;
          }
        }
        else if (((*(byte *)(psVar10 + 2) & 0x10) != 0) &&
                ((uVar7 & 1 << (uint)*(byte *)(psVar10 + 3)) == 0)) {
          puVar6[*(byte *)(psVar10 + 3)] = (int)psVar10 - *(int *)(iVar11 + 0x20);
          uVar7 = uVar7 | 1 << (uint)*(byte *)(psVar10 + 3);
        }
      }
      else {
        if (*psVar10 == 0x6e) {
          (**(code **)(*DAT_803dd71c + 0xc))(psVar10);
        }
        if (*psVar10 == 5) {
          (**(code **)(*DAT_803dd6ec + 0xc))(psVar10);
        }
      }
      pbVar1 = (byte *)(psVar10 + 1);
      psVar10 = psVar10 + (uint)*pbVar1 * 2;
    }
    if (in_r6 == 0) {
      uVar4 = puVar6[0x21];
      uVar7 = uVar9;
      if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar9)) {
        uVar7 = uVar4;
      }
      iVar11 = 4;
      puVar5 = puVar6;
      do {
        uVar4 = *puVar5;
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[1];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[2];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[3];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[4];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[5];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[6];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        uVar4 = puVar5[7];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar7)) {
          uVar7 = uVar4;
        }
        puVar5 = puVar5 + 8;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      puVar6[0x22] = uVar7;
      if (puVar6[0x21] == 0xffffffff) {
        puVar6[0x20] = uVar9;
      }
      else {
        puVar6[0x20] = puVar6[0x21];
      }
    }
  }
  FUN_80286880();
  return;
}

