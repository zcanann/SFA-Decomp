// Function: FUN_8027b53c
// Entry: 8027b53c
// Size: 488 bytes

uint FUN_8027b53c(byte param_1)

{
  uint uVar1;
  uint uVar2;
  short sVar3;
  undefined4 uVar4;
  undefined2 uVar5;
  undefined uVar6;
  byte bVar7;
  undefined1 *puVar8;
  int iVar9;
  
  puVar8 = &DAT_803cbef0;
  for (bVar7 = 0; bVar7 < DAT_803cbef0; bVar7 = bVar7 + 1) {
    if ((puVar8[8] != '\0') && (puVar8[0xb] == param_1)) {
      puVar8[8] = 0;
      (&DAT_803cc7f8)[(byte)puVar8[0xb]] = 0xff;
    }
    puVar8 = puVar8 + 0x24;
  }
  bVar7 = 0;
  puVar8 = &DAT_803cbef0;
  do {
    if (DAT_803cbef0 <= bVar7) {
      bVar7 = 0xff;
LAB_8027b600:
      uVar1 = (uint)bVar7;
      uVar2 = (uint)param_1;
      (&DAT_803cc7f8)[uVar2] = bVar7;
      if (uVar1 == 0xff) {
        FUN_80283da0(uVar2,0,0);
      }
      else {
        uVar4 = FUN_80284d9c((uint)(byte)(&DAT_803cc7f8)[uVar2],(undefined4 *)0x0);
        FUN_80283da0(uVar2,uVar4,DAT_803cbef4);
        uVar5 = FUN_80283de8(uVar2);
        iVar9 = uVar1 * 0x24;
        *(undefined2 *)(iVar9 + -0x7fc340f8) = uVar5;
        sVar3 = DAT_803cc838;
        do {
          DAT_803cc838 = sVar3;
          bVar7 = 0;
          for (puVar8 = &DAT_803cbef0;
              (bVar7 < DAT_803cbef0 &&
              ((puVar8[8] == '\0' || (*(short *)(puVar8 + 0x1a) != DAT_803cc838))));
              puVar8 = puVar8 + 0x24) {
            bVar7 = bVar7 + 1;
          }
          sVar3 = DAT_803cc838 + 1;
        } while (bVar7 != DAT_803cbef0);
        (&DAT_803cbf0a)[uVar1 * 0x12] = DAT_803cc838;
        DAT_803cc838 = sVar3;
        uVar6 = FUN_80283dd4(uVar2);
        (&DAT_803cbefa)[iVar9] = uVar6;
        (&DAT_803cbefb)[iVar9] = param_1;
        if (DAT_803cc83c != (code *)0x0) {
          (*DAT_803cc83c)(0,iVar9 + -0x7fc340f8);
          return (uint)CONCAT21((&DAT_803cbf0a)[uVar1 * 0x12],param_1);
        }
        FUN_80283da0(uVar2,0,0);
      }
      return 0xffffffff;
    }
    if (puVar8[8] == '\0') {
      (&DAT_803cbef8)[(uint)bVar7 * 0x24] = 1;
      (&DAT_803cbefc)[(uint)bVar7 * 9] = 0;
      goto LAB_8027b600;
    }
    puVar8 = puVar8 + 0x24;
    bVar7 = bVar7 + 1;
  } while( true );
}

