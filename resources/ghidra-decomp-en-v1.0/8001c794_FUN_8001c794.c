// Function: FUN_8001c794
// Entry: 8001c794
// Size: 936 bytes

void FUN_8001c794(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined2 *puVar10;
  int iVar11;
  undefined4 *puVar12;
  short *psVar13;
  int iVar14;
  int iVar15;
  
  iVar11 = 1;
  psVar13 = (short *)0x803db3ea;
  puVar12 = (undefined4 *)0x803dca2c;
  while( true ) {
    psVar13 = psVar13 + -1;
    puVar12 = puVar12 + -1;
    bVar1 = iVar11 == 0;
    iVar11 = iVar11 + -1;
    if (bVar1) break;
    uVar6 = FUN_80054d54((int)*psVar13);
    *puVar12 = uVar6;
  }
  DAT_803dca24 = FUN_80054c98(0x10,0x10,5,0,0,0,0,1,1);
  puVar10 = (undefined2 *)(DAT_803dca24 + 0x60);
  iVar14 = 0;
  iVar11 = 0;
  do {
    iVar9 = 0;
    iVar7 = 0;
    iVar15 = 2;
    do {
      iVar2 = iVar9 + 1;
      iVar3 = iVar9 + 2;
      iVar4 = iVar9 + 3;
      iVar5 = iVar11 * 0x20;
      *puVar10 = *(undefined2 *)((int)&DAT_802c9f00 + iVar7 + iVar5);
      puVar10[1] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar2];
      puVar10[2] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar3];
      puVar10[3] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar4];
      puVar10[4] = *(undefined2 *)((int)&DAT_802c9f20 + iVar7 + iVar5);
      puVar10[5] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar2];
      puVar10[6] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar3];
      puVar10[7] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar4];
      puVar10[8] = *(undefined2 *)((int)&DAT_802c9f40 + iVar7 + iVar5);
      puVar10[9] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar2];
      puVar10[10] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar3];
      puVar10[0xb] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar4];
      iVar5 = iVar5 + 0xf;
      puVar10[0xc] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar7 + iVar5);
      puVar10[0xd] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar2 * 2 + iVar5);
      puVar10[0xe] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar3 * 2 + iVar5);
      puVar10[0xf] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar4 * 2 + iVar5);
      iVar8 = iVar7 + 8;
      iVar2 = iVar9 + 5;
      iVar3 = iVar9 + 6;
      iVar4 = iVar9 + 7;
      iVar5 = iVar11 * 0x20;
      puVar10[0x10] = *(undefined2 *)((int)&DAT_802c9f00 + iVar8 + iVar5);
      puVar10[0x11] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar2];
      puVar10[0x12] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar3];
      puVar10[0x13] = (&DAT_802c9f00)[iVar11 * 0x10 + iVar4];
      puVar10[0x14] = *(undefined2 *)((int)&DAT_802c9f20 + iVar8 + iVar5);
      puVar10[0x15] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar2];
      puVar10[0x16] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar3];
      puVar10[0x17] = (&DAT_802c9f20)[iVar11 * 0x10 + iVar4];
      puVar10[0x18] = *(undefined2 *)((int)&DAT_802c9f40 + iVar8 + iVar5);
      puVar10[0x19] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar2];
      puVar10[0x1a] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar3];
      puVar10[0x1b] = (&DAT_802c9f40)[iVar11 * 0x10 + iVar4];
      iVar5 = iVar5 + 0xf;
      puVar10[0x1c] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar8 + iVar5);
      puVar10[0x1d] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar2 * 2 + iVar5);
      puVar10[0x1e] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar3 * 2 + iVar5);
      puVar10[0x1f] = *(undefined2 *)(s_H_H_H_H_H_H_H_H_802c9f51 + iVar4 * 2 + iVar5);
      puVar10 = puVar10 + 0x20;
      iVar9 = iVar9 + 8;
      iVar7 = iVar7 + 0x10;
      iVar15 = iVar15 + -1;
    } while (iVar15 != 0);
    iVar11 = iVar11 + 4;
    iVar14 = iVar14 + 1;
  } while (iVar14 < 4);
  FUN_802419e8(DAT_803dca24 + 0x60,0x200);
  DAT_803dca20 = FUN_80054c98(0x14,0x14,5,0,0,0,0,1,1);
  puVar10 = (undefined2 *)(DAT_803dca20 + 0x60);
  iVar14 = 0;
  iVar11 = 0;
  do {
    iVar9 = 0;
    iVar7 = 0;
    iVar15 = 5;
    do {
      iVar5 = iVar9 + 1;
      iVar2 = iVar9 + 2;
      iVar3 = iVar9 + 3;
      iVar4 = iVar11 * 0x28;
      *puVar10 = *(undefined2 *)((int)&DAT_802ca100 + iVar7 + iVar4);
      puVar10[1] = (&DAT_802ca100)[iVar11 * 0x14 + iVar5];
      puVar10[2] = (&DAT_802ca100)[iVar11 * 0x14 + iVar2];
      puVar10[3] = (&DAT_802ca100)[iVar11 * 0x14 + iVar3];
      puVar10[4] = *(undefined2 *)((int)&DAT_802ca128 + iVar7 + iVar4);
      puVar10[5] = (&DAT_802ca128)[iVar11 * 0x14 + iVar5];
      puVar10[6] = (&DAT_802ca128)[iVar11 * 0x14 + iVar2];
      puVar10[7] = (&DAT_802ca128)[iVar11 * 0x14 + iVar3];
      puVar10[8] = *(undefined2 *)((int)&DAT_802ca150 + iVar7 + iVar4);
      puVar10[9] = (&DAT_802ca150)[iVar11 * 0x14 + iVar5];
      puVar10[10] = (&DAT_802ca150)[iVar11 * 0x14 + iVar2];
      puVar10[0xb] = (&DAT_802ca150)[iVar11 * 0x14 + iVar3];
      puVar10[0xc] = *(undefined2 *)((int)&DAT_802ca178 + iVar7 + iVar4);
      puVar10[0xd] = (&DAT_802ca178)[iVar11 * 0x14 + iVar5];
      puVar10[0xe] = (&DAT_802ca178)[iVar11 * 0x14 + iVar2];
      puVar10[0xf] = (&DAT_802ca178)[iVar11 * 0x14 + iVar3];
      puVar10 = puVar10 + 0x10;
      iVar9 = iVar9 + 4;
      iVar7 = iVar7 + 8;
      iVar15 = iVar15 + -1;
    } while (iVar15 != 0);
    iVar11 = iVar11 + 4;
    iVar14 = iVar14 + 1;
  } while (iVar14 < 5);
  FUN_802419e8(DAT_803dca20 + 0x60,800);
  return;
}

