// Function: FUN_80265290
// Entry: 80265290
// Size: 588 bytes

void FUN_80265290(void)

{
  char cVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  
  puVar2 = (undefined4 *)(*(uint *)(DAT_803de210 + 0x69c) & 0xfffffffc);
  uVar3 = *(uint *)(DAT_803de210 + 0x69c) & 3;
  if (*(int *)(DAT_803de210 + 0x6a4) == 0x21) {
    *(int *)(DAT_803de210 + 0x6a4) = uVar3 * 8 + 1;
  }
  else {
    *(int *)(DAT_803de210 + 0x6a4) = *(int *)(DAT_803de210 + 0x6a4) + (3 - uVar3) * -8;
  }
  uVar3 = 0;
  iVar5 = 0;
  *(undefined4 **)(DAT_803de210 + 0x69c) = puVar2;
  *(undefined4 *)(DAT_803de210 + 0x6a0) = *puVar2;
  do {
    if (((uint)*(byte *)(DAT_803de210 + 0x6a8) & 1 << uVar3) != 0) {
      iVar10 = 0x10;
      uVar8 = 0;
      iVar4 = iVar5;
      do {
        *(undefined *)(iVar5 + DAT_803de210 + uVar8 + 0x300) = 0xff;
        for (uVar9 = 0; uVar9 < 5; uVar9 = uVar9 + 1) {
          iVar7 = iVar5 + DAT_803de210 + uVar9 * 4;
          uVar6 = uVar8 >> 4 - uVar9;
          if ((int)uVar6 <= *(int *)(iVar7 + 0x348)) {
            cVar1 = (char)uVar9;
            uVar9 = 99;
            *(undefined *)(iVar4 + DAT_803de210 + 0x300) =
                 *(undefined *)
                  (uVar6 + *(int *)(iVar7 + 0x390) + *(int *)(iVar5 + DAT_803de210 + 0x340));
            *(char *)(iVar4 + DAT_803de210 + 800) = cVar1 + '\x01';
          }
        }
        *(undefined *)(iVar5 + DAT_803de210 + uVar8 + 1 + 0x300) = 0xff;
        for (uVar9 = 0; uVar9 < 5; uVar9 = uVar9 + 1) {
          iVar7 = iVar5 + DAT_803de210 + uVar9 * 4;
          uVar6 = uVar8 + 1 >> 4 - uVar9;
          if ((int)uVar6 <= *(int *)(iVar7 + 0x348)) {
            cVar1 = (char)uVar9;
            uVar9 = 99;
            *(undefined *)(iVar4 + 1 + DAT_803de210 + 0x300) =
                 *(undefined *)
                  (uVar6 + *(int *)(iVar7 + 0x390) + *(int *)(iVar5 + DAT_803de210 + 0x340));
            *(char *)(iVar4 + 1 + DAT_803de210 + 800) = cVar1 + '\x01';
          }
        }
        iVar4 = iVar4 + 2;
        uVar8 = uVar8 + 2;
        iVar10 = iVar10 + -1;
      } while (iVar10 != 0);
    }
    uVar3 = uVar3 + 1;
    iVar5 = iVar5 + 0xe0;
  } while (uVar3 < 4);
  DAT_803de100 = DAT_803de210 + (uint)*(byte *)(DAT_803de210 + 0x681) * 0x1c0 + 0x300;
  DAT_803de120 = DAT_803de210 + (uint)*(byte *)(DAT_803de210 + 0x687) * 0x1c0 + 0x300;
  DAT_803de140 = DAT_803de210 + (uint)*(byte *)(DAT_803de210 + 0x68d) * 0x1c0 + 0x300;
  DAT_803de160 = DAT_803de210 + ((uint)*(byte *)(DAT_803de210 + 0x682) * 2 + 1) * 0xe0 + 0x300;
  DAT_803de180 = DAT_803de210 + ((uint)*(byte *)(DAT_803de210 + 0x688) * 2 + 1) * 0xe0 + 0x300;
  DAT_803de1a0 = DAT_803de210 + ((uint)*(byte *)(DAT_803de210 + 0x68e) * 2 + 1) * 0xe0 + 0x300;
  return;
}

