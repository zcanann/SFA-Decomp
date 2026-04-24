// Function: FUN_8027add8
// Entry: 8027add8
// Size: 488 bytes

uint FUN_8027add8(byte param_1)

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
  
  puVar8 = &DAT_803cb290;
  for (bVar7 = 0; bVar7 < DAT_803cb290; bVar7 = bVar7 + 1) {
    if ((puVar8[8] != '\0') && (puVar8[0xb] == param_1)) {
      puVar8[8] = 0;
      (&DAT_803cbb98)[(byte)puVar8[0xb]] = 0xff;
    }
    puVar8 = puVar8 + 0x24;
  }
  bVar7 = 0;
  puVar8 = &DAT_803cb290;
  do {
    if (DAT_803cb290 <= bVar7) {
      bVar7 = 0xff;
LAB_8027ae9c:
      uVar1 = (uint)bVar7;
      uVar2 = (uint)param_1;
      (&DAT_803cbb98)[uVar2] = bVar7;
      if (uVar1 == 0xff) {
        FUN_8028363c(uVar2,0,0);
      }
      else {
        uVar4 = FUN_80284638((&DAT_803cbb98)[uVar2],0);
        FUN_8028363c(uVar2,uVar4,DAT_803cb294);
        uVar5 = FUN_80283684(uVar2);
        iVar9 = uVar1 * 0x24;
        *(undefined2 *)(iVar9 + -0x7fc34d58) = uVar5;
        sVar3 = DAT_803cbbd8;
        do {
          DAT_803cbbd8 = sVar3;
          bVar7 = 0;
          for (puVar8 = &DAT_803cb290;
              (bVar7 < DAT_803cb290 &&
              ((puVar8[8] == '\0' || (*(short *)(puVar8 + 0x1a) != DAT_803cbbd8))));
              puVar8 = puVar8 + 0x24) {
            bVar7 = bVar7 + 1;
          }
          sVar3 = DAT_803cbbd8 + 1;
        } while (bVar7 != DAT_803cb290);
        (&DAT_803cb2aa)[uVar1 * 0x12] = DAT_803cbbd8;
        DAT_803cbbd8 = sVar3;
        uVar6 = FUN_80283670(uVar2);
        (&DAT_803cb29a)[iVar9] = uVar6;
        (&DAT_803cb29b)[iVar9] = param_1;
        if (DAT_803cbbdc != (code *)0x0) {
          (*DAT_803cbbdc)(0,iVar9 + -0x7fc34d58);
          return (uint)CONCAT21((&DAT_803cb2aa)[uVar1 * 0x12],param_1);
        }
        FUN_8028363c(uVar2,0,0);
      }
      return 0xffffffff;
    }
    if (puVar8[8] == '\0') {
      (&DAT_803cb298)[(uint)bVar7 * 0x24] = 1;
      (&DAT_803cb29c)[(uint)bVar7 * 9] = 0;
      goto LAB_8027ae9c;
    }
    puVar8 = puVar8 + 0x24;
    bVar7 = bVar7 + 1;
  } while( true );
}

