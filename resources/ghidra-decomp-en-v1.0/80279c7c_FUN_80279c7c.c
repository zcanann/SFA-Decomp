// Function: FUN_80279c7c
// Entry: 80279c7c
// Size: 816 bytes

void FUN_80279c7c(void)

{
  char cVar1;
  byte bVar2;
  int iVar3;
  undefined1 *puVar4;
  uint uVar5;
  undefined *puVar6;
  char *pcVar7;
  uint uVar8;
  uint uVar9;
  
  uVar8 = 0;
  uVar5 = (uint)DAT_803bd360;
  if (uVar5 != 0) {
    if (8 < uVar5) {
      uVar9 = uVar5 - 1 >> 3;
      pcVar7 = &DAT_803cb190;
      if (uVar5 != 8) {
        do {
          cVar1 = (char)uVar8;
          *pcVar7 = cVar1 + -1;
          pcVar7[1] = cVar1 + '\x01';
          *(undefined2 *)(pcVar7 + 2) = 1;
          pcVar7[4] = cVar1;
          pcVar7[5] = cVar1 + '\x02';
          uVar8 = uVar8 + 8;
          *(undefined2 *)(pcVar7 + 6) = 1;
          pcVar7[8] = cVar1 + '\x01';
          pcVar7[9] = cVar1 + '\x03';
          *(undefined2 *)(pcVar7 + 10) = 1;
          pcVar7[0xc] = cVar1 + '\x02';
          pcVar7[0xd] = cVar1 + '\x04';
          *(undefined2 *)(pcVar7 + 0xe) = 1;
          pcVar7[0x10] = cVar1 + '\x03';
          pcVar7[0x11] = cVar1 + '\x05';
          *(undefined2 *)(pcVar7 + 0x12) = 1;
          pcVar7[0x14] = cVar1 + '\x04';
          pcVar7[0x15] = cVar1 + '\x06';
          *(undefined2 *)(pcVar7 + 0x16) = 1;
          pcVar7[0x18] = cVar1 + '\x05';
          pcVar7[0x19] = cVar1 + '\a';
          *(undefined2 *)(pcVar7 + 0x1a) = 1;
          pcVar7[0x1c] = cVar1 + '\x06';
          pcVar7[0x1d] = cVar1 + '\b';
          *(undefined2 *)(pcVar7 + 0x1e) = 1;
          pcVar7 = pcVar7 + 0x20;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
    }
    pcVar7 = &DAT_803cb190 + uVar8 * 4;
    iVar3 = DAT_803bd360 - uVar8;
    if (uVar8 < DAT_803bd360) {
      do {
        cVar1 = (char)uVar8;
        *pcVar7 = cVar1 + -1;
        uVar8 = uVar8 + 1;
        pcVar7[1] = cVar1 + '\x01';
        *(undefined2 *)(pcVar7 + 2) = 1;
        pcVar7 = pcVar7 + 4;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  bVar2 = DAT_803bd360;
  DAT_803cb190 = 0xff;
  uVar5 = 0;
  uVar8 = (uint)DAT_803bd360;
  (&DAT_803cb18d)[uVar8 * 4] = 0xff;
  DAT_803de300 = bVar2 - 1;
  DAT_803de301 = 0;
  if (uVar8 != 0) {
    if (8 < uVar8) {
      uVar9 = uVar8 - 1 >> 3;
      puVar6 = &DAT_803cab90;
      if (uVar8 != 8) {
        do {
          *(undefined2 *)(puVar6 + 2) = 0;
          uVar5 = uVar5 + 8;
          *(undefined2 *)(puVar6 + 6) = 0;
          *(undefined2 *)(puVar6 + 10) = 0;
          *(undefined2 *)(puVar6 + 0xe) = 0;
          *(undefined2 *)(puVar6 + 0x12) = 0;
          *(undefined2 *)(puVar6 + 0x16) = 0;
          *(undefined2 *)(puVar6 + 0x1a) = 0;
          *(undefined2 *)(puVar6 + 0x1e) = 0;
          puVar6 = puVar6 + 0x20;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
      }
    }
    puVar6 = &DAT_803cab90 + uVar5 * 4;
    iVar3 = DAT_803bd360 - uVar5;
    if (uVar5 < DAT_803bd360) {
      do {
        *(undefined2 *)(puVar6 + 2) = 0;
        puVar6 = puVar6 + 4;
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
  }
  iVar3 = 4;
  puVar4 = &DAT_803cac90;
  do {
    *puVar4 = 0xff;
    puVar4[1] = 0xff;
    puVar4[2] = 0xff;
    puVar4[3] = 0xff;
    puVar4[4] = 0xff;
    puVar4[5] = 0xff;
    puVar4[6] = 0xff;
    puVar4[7] = 0xff;
    puVar4[8] = 0xff;
    puVar4[9] = 0xff;
    puVar4[10] = 0xff;
    puVar4[0xb] = 0xff;
    puVar4[0xc] = 0xff;
    puVar4[0xd] = 0xff;
    puVar4[0xe] = 0xff;
    puVar4[0xf] = 0xff;
    puVar4[0x10] = 0xff;
    puVar4[0x11] = 0xff;
    puVar4[0x12] = 0xff;
    puVar4[0x13] = 0xff;
    puVar4[0x14] = 0xff;
    puVar4[0x15] = 0xff;
    puVar4[0x16] = 0xff;
    puVar4[0x17] = 0xff;
    puVar4[0x18] = 0xff;
    puVar4[0x19] = 0xff;
    puVar4[0x1a] = 0xff;
    puVar4[0x1b] = 0xff;
    puVar4[0x1c] = 0xff;
    puVar4[0x1d] = 0xff;
    puVar4[0x1e] = 0xff;
    puVar4[0x1f] = 0xff;
    puVar4[0x20] = 0xff;
    puVar4[0x21] = 0xff;
    puVar4[0x22] = 0xff;
    puVar4[0x23] = 0xff;
    puVar4[0x24] = 0xff;
    puVar4[0x25] = 0xff;
    puVar4[0x26] = 0xff;
    puVar4[0x27] = 0xff;
    puVar4[0x28] = 0xff;
    puVar4[0x29] = 0xff;
    puVar4[0x2a] = 0xff;
    puVar4[0x2b] = 0xff;
    puVar4[0x2c] = 0xff;
    puVar4[0x2d] = 0xff;
    puVar4[0x2e] = 0xff;
    puVar4[0x2f] = 0xff;
    puVar4[0x30] = 0xff;
    puVar4[0x31] = 0xff;
    puVar4[0x32] = 0xff;
    puVar4[0x33] = 0xff;
    puVar4[0x34] = 0xff;
    puVar4[0x35] = 0xff;
    puVar4[0x36] = 0xff;
    puVar4[0x37] = 0xff;
    puVar4[0x38] = 0xff;
    puVar4[0x39] = 0xff;
    puVar4[0x3a] = 0xff;
    puVar4[0x3b] = 0xff;
    puVar4[0x3c] = 0xff;
    puVar4[0x3d] = 0xff;
    puVar4[0x3e] = 0xff;
    puVar4[0x3f] = 0xff;
    puVar4 = puVar4 + 0x40;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_803de2fc = 0xffff;
  DAT_803de2fe = 0;
  DAT_803de2ff = 0;
  return;
}

