// Function: FUN_8005972c
// Entry: 8005972c
// Size: 804 bytes

void FUN_8005972c(void)

{
  short *psVar1;
  short sVar2;
  bool bVar3;
  uint uVar4;
  uint *puVar5;
  uint *puVar6;
  int iVar7;
  int in_r6;
  uint uVar8;
  int iVar9;
  uint uVar10;
  short *psVar11;
  undefined8 uVar12;
  
  uVar12 = FUN_802860d0();
  iVar7 = (int)((ulonglong)uVar12 >> 0x20);
  puVar6 = (uint *)uVar12;
  bVar3 = false;
  uVar8 = 0;
  psVar11 = *(short **)(iVar7 + 0x20);
  uVar10 = (uint)*(ushort *)(iVar7 + 8);
  if (uVar10 != 0) {
    iVar9 = 0;
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
    for (; iVar9 < (int)uVar10; iVar9 = iVar9 + (uint)*(byte *)psVar1 * 4) {
      if (in_r6 == 0) {
        sVar2 = *psVar11;
        if ((sVar2 == 0x6e) || (sVar2 == 5)) {
          if (sVar2 == 0x6e) {
            uVar12 = (**(code **)(*DAT_803dca9c + 8))(psVar11);
          }
          else {
            uVar12 = (**(code **)(*DAT_803dca6c + 8))(psVar11);
          }
          if (!bVar3) {
            puVar6[0x21] = (int)psVar11 - *(int *)(iVar7 + 0x20);
            bVar3 = true;
          }
        }
        else if ((*(byte *)(psVar11 + 2) & 0x10) != 0) {
          uVar12 = CONCAT44((int)((ulonglong)uVar12 >> 0x20),1);
          if ((uVar8 & 1 << (uint)*(byte *)(psVar11 + 3)) == 0) {
            uVar4 = (int)psVar11 - *(int *)(iVar7 + 0x20);
            uVar12 = CONCAT44(uVar4,1);
            puVar6[*(byte *)(psVar11 + 3)] = uVar4;
            uVar8 = uVar8 | 1 << (uint)*(byte *)(psVar11 + 3);
          }
        }
      }
      else {
        if (*psVar11 == 0x6e) {
          uVar12 = (**(code **)(*DAT_803dca9c + 0xc))(psVar11);
        }
        if (*psVar11 == 5) {
          uVar12 = (**(code **)(*DAT_803dca6c + 0xc))(psVar11);
        }
      }
      psVar1 = psVar11 + 1;
      psVar11 = psVar11 + (uint)*(byte *)psVar1 * 2;
    }
    if (in_r6 == 0) {
      uVar4 = puVar6[0x21];
      uVar8 = uVar10;
      if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar10)) {
        uVar8 = uVar4;
      }
      iVar7 = 0;
      iVar9 = 4;
      puVar5 = puVar6;
      do {
        uVar4 = *puVar5;
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[1];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[2];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[3];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[4];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[5];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[6];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        uVar4 = puVar5[7];
        if ((uVar4 != 0xffffffff) && ((int)uVar4 < (int)uVar8)) {
          uVar8 = uVar4;
        }
        puVar5 = puVar5 + 8;
        iVar7 = iVar7 + 7;
        uVar12 = CONCAT44(puVar5,iVar7);
        iVar9 = iVar9 + -1;
      } while (iVar9 != 0);
      puVar6[0x22] = uVar8;
      if (puVar6[0x21] == 0xffffffff) {
        puVar6[0x20] = uVar10;
      }
      else {
        puVar6[0x20] = puVar6[0x21];
        uVar12 = CONCAT44(puVar5,iVar7);
      }
    }
  }
  FUN_8028611c((int)((ulonglong)uVar12 >> 0x20),(int)uVar12);
  return;
}

