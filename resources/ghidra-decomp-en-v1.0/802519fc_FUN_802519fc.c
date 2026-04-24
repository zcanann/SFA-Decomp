// Function: FUN_802519fc
// Entry: 802519fc
// Size: 764 bytes

uint FUN_802519fc(void)

{
  undefined4 *puVar1;
  int iVar2;
  uint uVar3;
  undefined4 *puVar4;
  uint uVar5;
  uint uVar6;
  undefined *puVar7;
  uint uVar8;
  uint uVar9;
  undefined8 uVar10;
  
  puVar7 = &DAT_cc006400;
  uVar5 = read_volatile_4(DAT_cc006434);
  uVar6 = read_volatile_4(DAT_cc006438);
  write_volatile_4(DAT_cc006434,uVar5 & 0xfffffffe | 0x80000000);
  if (DAT_8032e240 != -1) {
    uVar10 = FUN_80246c70();
    iVar2 = DAT_8032e240 * 8;
    *(int *)(&DAT_803ae344 + iVar2) = (int)uVar10;
    uVar3 = 0;
    *(int *)(&DAT_803ae340 + iVar2) = (int)((ulonglong)uVar10 >> 0x20);
    uVar5 = DAT_8032e248 >> 2;
    puVar4 = DAT_8032e24c;
    if (uVar5 != 0) {
      if ((8 < uVar5) && (uVar8 = uVar5 - 1 >> 3, uVar5 != 8)) {
        do {
          uVar3 = uVar3 + 8;
          *puVar4 = *(undefined4 *)(puVar7 + 0x80);
          puVar4[1] = *(undefined4 *)(puVar7 + 0x84);
          puVar4[2] = *(undefined4 *)(puVar7 + 0x88);
          puVar4[3] = *(undefined4 *)(puVar7 + 0x8c);
          puVar4[4] = *(undefined4 *)(puVar7 + 0x90);
          puVar4[5] = *(undefined4 *)(puVar7 + 0x94);
          puVar4[6] = *(undefined4 *)(puVar7 + 0x98);
          puVar1 = (undefined4 *)(puVar7 + 0x9c);
          puVar7 = puVar7 + 0x20;
          puVar4[7] = *puVar1;
          puVar4 = puVar4 + 8;
          uVar8 = uVar8 - 1;
        } while (uVar8 != 0);
      }
      puVar7 = &DAT_cc006400 + uVar3 * 4;
      iVar2 = uVar5 - uVar3;
      if (uVar3 < uVar5) {
        do {
          puVar1 = (undefined4 *)(puVar7 + 0x80);
          puVar7 = puVar7 + 4;
          uVar3 = uVar3 + 1;
          *puVar4 = *puVar1;
          puVar4 = puVar4 + 1;
          iVar2 = iVar2 + -1;
        } while (iVar2 != 0);
      }
    }
    uVar5 = DAT_8032e248 & 3;
    if (uVar5 != 0) {
      uVar8 = (&DAT_cc006480)[uVar3];
      uVar3 = 0;
      if (uVar5 != 0) {
        if ((8 < uVar5) && (uVar9 = uVar5 - 1 >> 3, uVar5 != 8)) {
          do {
            *(char *)puVar4 = (char)(uVar8 >> (3 - uVar3) * 8);
            *(char *)((int)puVar4 + 1) = (char)(uVar8 >> (3 - (uVar3 + 1)) * 8);
            *(char *)((int)puVar4 + 2) = (char)(uVar8 >> (3 - (uVar3 + 2)) * 8);
            *(char *)((int)puVar4 + 3) = (char)(uVar8 >> uVar3 * -8);
            *(char *)(puVar4 + 1) = (char)(uVar8 >> (3 - (uVar3 + 4)) * 8);
            *(char *)((int)puVar4 + 5) = (char)(uVar8 >> (3 - (uVar3 + 5)) * 8);
            *(char *)((int)puVar4 + 6) = (char)(uVar8 >> (3 - (uVar3 + 6)) * 8);
            *(char *)((int)puVar4 + 7) = (char)(uVar8 >> (3 - (uVar3 + 7)) * 8);
            puVar4 = puVar4 + 2;
            uVar3 = uVar3 + 8;
            uVar9 = uVar9 - 1;
          } while (uVar9 != 0);
        }
        iVar2 = uVar5 - uVar3;
        if (uVar3 < uVar5) {
          do {
            *(char *)puVar4 = (char)(uVar8 >> (3 - uVar3) * 8);
            puVar4 = (undefined4 *)((int)puVar4 + 1);
            uVar3 = uVar3 + 1;
            iVar2 = iVar2 + -1;
          } while (iVar2 != 0);
        }
      }
    }
    uVar5 = read_volatile_4(DAT_cc006434);
    if ((uVar5 & 0x20000000) == 0) {
      uVar10 = FUN_80246c70();
      *(int *)(&DAT_803ae324 + DAT_8032e240 * 8) = (int)uVar10;
      uVar6 = 0;
      *(int *)(&DAT_803ae320 + DAT_8032e240 * 8) = (int)((ulonglong)uVar10 >> 0x20);
    }
    else {
      uVar5 = uVar6 >> (3 - DAT_8032e240) * 8;
      uVar6 = uVar5 & 0xf;
      if (((uVar5 & 8) != 0) && ((*(uint *)(&DAT_8032e254 + DAT_8032e240 * 4) & 0x80) == 0)) {
        *(uint *)(&DAT_8032e254 + DAT_8032e240 * 4) = 8;
      }
      if (uVar6 == 0) {
        uVar6 = 4;
      }
    }
    DAT_8032e240 = -1;
  }
  return uVar6;
}

