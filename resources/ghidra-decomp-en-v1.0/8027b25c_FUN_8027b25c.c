// Function: FUN_8027b25c
// Entry: 8027b25c
// Size: 452 bytes

void FUN_8027b25c(void)

{
  byte bVar1;
  byte bVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  byte *pbVar8;
  uint uVar9;
  undefined1 *puVar10;
  
  puVar10 = &DAT_803cb290;
  if (DAT_803cbbdc != 0) {
    uVar9 = 0;
    do {
      if ((puVar10[0x908] != -1) && (iVar3 = FUN_8028365c(uVar9), iVar3 != 0)) {
        bVar1 = puVar10[0x908];
        iVar3 = (uint)bVar1 * 0x24;
        pbVar8 = &DAT_803cb298 + iVar3;
        uVar4 = FUN_80283c08(uVar9);
        uVar7 = uVar4;
        if ((&DAT_803cb29a)[iVar3] == '\x05') {
          uVar7 = (uVar4 / 0xe) * 0xe;
        }
        bVar2 = *pbVar8;
        if (bVar2 == 2) {
          uVar5 = FUN_80283f58((&DAT_803cb29b)[iVar3]);
          if (CONCAT21((&DAT_803cb2aa)[(uint)bVar1 * 0x12],(&DAT_803cb29b)[iVar3]) == uVar5) {
            FUN_8027b06c(pbVar8,uVar7);
            uVar7 = *(uint *)(&DAT_803cb2a4 + iVar3);
            if (uVar4 < uVar7) {
              *(uint *)(&DAT_803cb2a0 + iVar3) =
                   *(int *)(&DAT_803cb2a0 + iVar3) - (DAT_803cb294 - (uVar7 - uVar4));
            }
            else {
              *(uint *)(&DAT_803cb2a0 + iVar3) = *(int *)(&DAT_803cb2a0 + iVar3) - (uVar4 - uVar7);
            }
            *(uint *)(&DAT_803cb2a4 + iVar3) = uVar4;
            if (*(int *)(&DAT_803cb2a0 + iVar3) <
                (int)((uint)*(ushort *)
                             (DAT_803de268 + (uint)(byte)(&DAT_803cb29b)[iVar3] * 0x404 + 0x206) *
                      0xa0 + 0xfff) >> 0xc) {
              iVar6 = FUN_80283f80();
              if (iVar6 == 0) {
                FUN_8028343c((&DAT_803cb29b)[iVar3]);
              }
              *pbVar8 = 0;
              (&DAT_803cbb98)[(byte)(&DAT_803cb29b)[iVar3]] = 0xff;
            }
          }
          else {
            *pbVar8 = 0;
            (&DAT_803cbb98)[(byte)(&DAT_803cb29b)[iVar3]] = 0xff;
          }
        }
        else if ((bVar2 < 2) && (bVar2 != 0)) {
          FUN_8027b06c(pbVar8,uVar7);
        }
      }
      uVar9 = uVar9 + 1;
      puVar10 = puVar10 + 1;
    } while (uVar9 < 0x40);
  }
  return;
}

