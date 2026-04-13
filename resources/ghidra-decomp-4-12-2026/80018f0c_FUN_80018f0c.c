// Function: FUN_80018f0c
// Entry: 80018f0c
// Size: 660 bytes

undefined4 FUN_80018f0c(int param_1,uint param_2,uint *param_3)

{
  undefined *puVar1;
  uint uVar2;
  uint uVar3;
  uint *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int local_18 [2];
  
  iVar5 = 0;
  if (param_1 != 0) {
    while (uVar2 = FUN_80015cf0((byte *)(param_1 + iVar5),local_18), uVar2 != 0) {
      iVar5 = iVar5 + local_18[0];
      if ((0xdfff < uVar2) && (uVar2 < 0xf900)) {
        puVar4 = &DAT_802c8e70;
        iVar8 = 0x17;
        do {
          if (*puVar4 == uVar2) {
            uVar3 = puVar4[1];
            goto LAB_80018fb4;
          }
          if (puVar4[2] == uVar2) {
            uVar3 = puVar4[3];
            goto LAB_80018fb4;
          }
          puVar4 = puVar4 + 4;
          iVar8 = iVar8 + -1;
        } while (iVar8 != 0);
        uVar3 = 0;
LAB_80018fb4:
        if (uVar2 == param_2) {
          iVar8 = 0;
          if (0 < (int)uVar3) {
            if ((8 < (int)uVar3) && (uVar2 = uVar3 - 1 >> 3, puVar4 = param_3, 0 < (int)(uVar3 - 8))
               ) {
              do {
                *puVar4 = (uint)CONCAT11(*(undefined *)(param_1 + iVar5),
                                         *(undefined *)(param_1 + iVar5 + 1));
                puVar4[1] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 2),
                                           *(undefined *)(param_1 + iVar5 + 3));
                puVar4[2] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 4),
                                           *(undefined *)(param_1 + iVar5 + 5));
                puVar4[3] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 6),
                                           *(undefined *)(param_1 + iVar5 + 7));
                puVar4[4] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 8),
                                           *(undefined *)(param_1 + iVar5 + 9));
                puVar4[5] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 10),
                                           *(undefined *)(param_1 + iVar5 + 0xb));
                iVar6 = iVar5 + 0xe;
                puVar4[6] = (uint)CONCAT11(*(undefined *)(param_1 + iVar5 + 0xc),
                                           *(undefined *)(param_1 + iVar5 + 0xd));
                iVar7 = iVar5 + 0xf;
                iVar5 = iVar5 + 0x10;
                puVar4[7] = (uint)CONCAT11(*(undefined *)(param_1 + iVar6),
                                           *(undefined *)(param_1 + iVar7));
                puVar4 = puVar4 + 8;
                iVar8 = iVar8 + 8;
                uVar2 = uVar2 - 1;
              } while (uVar2 != 0);
            }
            puVar4 = param_3 + iVar8;
            iVar6 = uVar3 - iVar8;
            if (iVar8 < (int)uVar3) {
              do {
                iVar8 = iVar5 + 1;
                puVar1 = (undefined *)(param_1 + iVar5);
                iVar5 = iVar5 + 2;
                *puVar4 = (uint)CONCAT11(*puVar1,*(undefined *)(param_1 + iVar8));
                puVar4 = puVar4 + 1;
                iVar6 = iVar6 + -1;
              } while (iVar6 != 0);
            }
          }
          return 1;
        }
        iVar5 = iVar5 + uVar3 * 2;
      }
    }
  }
  return 0;
}

