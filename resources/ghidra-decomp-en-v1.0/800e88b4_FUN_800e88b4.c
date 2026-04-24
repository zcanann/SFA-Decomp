// Function: FUN_800e88b4
// Entry: 800e88b4
// Size: 504 bytes

int FUN_800e88b4(uint param_1,byte param_2,uint param_3,undefined *param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined1 *puVar4;
  undefined *puVar5;
  undefined1 *puVar6;
  int iVar7;
  uint uVar8;
  
  iVar2 = 0;
  iVar1 = (param_1 & 0xff) * 0x28;
  puVar6 = &DAT_803a31c4 + iVar1;
  iVar7 = 5;
  puVar4 = puVar6;
  do {
    if (*(uint *)(puVar4 + 0x1c) >> 1 < param_3) {
      iVar7 = 4;
      puVar5 = &DAT_803a31e4 + iVar1;
      uVar3 = 4 - iVar2;
      if (iVar2 < 4) {
        uVar8 = uVar3 >> 1;
        if (uVar8 == 0) goto LAB_800e89d8;
        do {
          *(uint *)(puVar5 + 0x1c) =
               *(uint *)(puVar6 + (iVar7 + -1) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x1c) & 1;
          puVar5[0x1f] = puVar6[(iVar7 + -1) * 8 + 0x1f] & 1 | puVar5[0x1f] & 0xfe;
          puVar5[0x20] = puVar5[0x18];
          puVar5[0x21] = puVar5[0x19];
          puVar5[0x22] = puVar5[0x1a];
          puVar5[0x23] = puVar5[0x1b];
          *(uint *)(puVar5 + 0x14) =
               *(uint *)(puVar6 + (iVar7 + -2) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x14) & 1;
          puVar5[0x17] = puVar6[(iVar7 + -2) * 8 + 0x1f] & 1 | puVar5[0x17] & 0xfe;
          puVar5[0x18] = puVar5[0x10];
          puVar5[0x19] = puVar5[0x11];
          puVar5[0x1a] = puVar5[0x12];
          puVar5[0x1b] = puVar5[0x13];
          puVar5 = puVar5 + -0x10;
          iVar7 = iVar7 + -2;
          uVar8 = uVar8 - 1;
        } while (uVar8 != 0);
        for (uVar3 = uVar3 & 1; uVar3 != 0; uVar3 = uVar3 - 1) {
LAB_800e89d8:
          *(uint *)(puVar5 + 0x1c) =
               *(uint *)(puVar6 + (iVar7 + -1) * 8 + 0x1c) & 0xfffffffe |
               *(uint *)(puVar5 + 0x1c) & 1;
          puVar5[0x1f] = puVar6[(iVar7 + -1) * 8 + 0x1f] & 1 | puVar5[0x1f] & 0xfe;
          puVar5[0x20] = puVar5[0x18];
          puVar5[0x21] = puVar5[0x19];
          puVar5[0x22] = puVar5[0x1a];
          puVar5[0x23] = puVar5[0x1b];
          puVar5 = puVar5 + -8;
          iVar7 = iVar7 + -1;
        }
      }
      iVar7 = iVar2 * 8;
      *(uint *)(puVar6 + iVar7 + 0x1c) = param_3 << 1 | *(uint *)(puVar6 + iVar7 + 0x1c) & 1;
      puVar6[iVar7 + 0x1f] = param_2 & 1 | puVar6[iVar7 + 0x1f] & 0xfe;
      iVar7 = iVar7 + iVar1;
      (&DAT_803a31c4)[iVar7 + 0x20] = *param_4;
      (&DAT_803a31c4)[iVar7 + 0x21] = param_4[1];
      (&DAT_803a31c4)[iVar7 + 0x22] = param_4[2];
      (&DAT_803a31c4)[iVar7 + 0x23] = param_4[3];
      return iVar2;
    }
    puVar4 = puVar4 + 8;
    iVar2 = iVar2 + 1;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  return -1;
}

