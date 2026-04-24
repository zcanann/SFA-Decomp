// Function: FUN_8027b9c0
// Entry: 8027b9c0
// Size: 452 bytes

void FUN_8027b9c0(void)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  byte *pbVar7;
  uint uVar8;
  undefined1 *puVar9;
  
  puVar9 = &DAT_803cbef0;
  if (DAT_803cc83c != 0) {
    uVar8 = 0;
    do {
      if ((puVar9[0x908] != -1) && (iVar3 = FUN_80283dc0(uVar8), iVar3 != 0)) {
        bVar1 = puVar9[0x908];
        iVar3 = (uint)bVar1 * 0x24;
        pbVar7 = &DAT_803cbef8 + iVar3;
        uVar4 = FUN_8028436c(uVar8);
        uVar6 = uVar4;
        if ((&DAT_803cbefa)[iVar3] == '\x05') {
          uVar6 = (uVar4 / 0xe) * 0xe;
        }
        bVar2 = *pbVar7;
        if (bVar2 == 2) {
          uVar5 = FUN_802846bc((uint)(byte)(&DAT_803cbefb)[iVar3]);
          if (CONCAT21((&DAT_803cbf0a)[(uint)bVar1 * 0x12],(&DAT_803cbefb)[iVar3]) == uVar5) {
            FUN_8027b7d0((int)pbVar7,uVar6);
            uVar6 = *(uint *)(&DAT_803cbf04 + iVar3);
            if (uVar4 < uVar6) {
              *(uint *)(&DAT_803cbf00 + iVar3) =
                   *(int *)(&DAT_803cbf00 + iVar3) - (DAT_803cbef4 - (uVar6 - uVar4));
            }
            else {
              *(uint *)(&DAT_803cbf00 + iVar3) = *(int *)(&DAT_803cbf00 + iVar3) - (uVar4 - uVar6);
            }
            *(uint *)(&DAT_803cbf04 + iVar3) = uVar4;
            if (*(int *)(&DAT_803cbf00 + iVar3) <
                (int)((uint)*(ushort *)
                             (DAT_803deee8 + (uint)(byte)(&DAT_803cbefb)[iVar3] * 0x404 + 0x206) *
                      0xa0 + 0xfff) >> 0xc) {
              uVar6 = FUN_802846e4((uint)(byte)(&DAT_803cbefb)[iVar3]);
              if (uVar6 == 0) {
                FUN_80283ba0((uint)(byte)(&DAT_803cbefb)[iVar3]);
              }
              *pbVar7 = 0;
              (&DAT_803cc7f8)[(byte)(&DAT_803cbefb)[iVar3]] = 0xff;
            }
          }
          else {
            *pbVar7 = 0;
            (&DAT_803cc7f8)[(byte)(&DAT_803cbefb)[iVar3]] = 0xff;
          }
        }
        else if ((bVar2 < 2) && (bVar2 != 0)) {
          FUN_8027b7d0((int)pbVar7,uVar6);
        }
      }
      uVar8 = uVar8 + 1;
      puVar9 = puVar9 + 1;
    } while (uVar8 < 0x40);
  }
  return;
}

