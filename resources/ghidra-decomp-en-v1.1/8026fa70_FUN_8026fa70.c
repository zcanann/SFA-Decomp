// Function: FUN_8026fa70
// Entry: 8026fa70
// Size: 560 bytes

int FUN_8026fa70(void)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined2 *puVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  
  puVar4 = &DAT_803b01b0;
  DAT_803deeb4 = 0;
  iVar7 = 4;
  DAT_803deeb0 = 0;
  puVar2 = &DAT_803b15b0;
  iVar6 = 0;
  puVar3 = &DAT_803bd8f0;
  do {
    if (iVar6 == 0) {
      DAT_803deeac = puVar2;
      puVar2[1] = 0;
    }
    else {
      puVar2[-0x61a] = puVar2;
      puVar2[1] = &DAT_803b15b0 + (iVar6 + -1) * 0x61a;
    }
    *(char *)((int)puVar2 + 9) = (char)iVar6;
    *(undefined *)(puVar2 + 2) = 0;
    *puVar3 = 0xffff;
    puVar3[1] = 0xffff;
    puVar3[2] = 0xffff;
    puVar3[3] = 0xffff;
    puVar3[4] = 0xffff;
    puVar3[5] = 0xffff;
    puVar3[6] = 0xffff;
    puVar3[7] = 0xffff;
    puVar3[8] = 0xffff;
    puVar3[9] = 0xffff;
    puVar3[10] = 0xffff;
    puVar3[0xb] = 0xffff;
    puVar3[0xc] = 0xffff;
    puVar3[0xd] = 0xffff;
    puVar3[0xe] = 0xffff;
    puVar3[0xf] = 0xffff;
    if (iVar6 + 1 == 0) {
      DAT_803deeac = puVar2 + 0x61a;
      puVar2[0x61b] = 0;
    }
    else {
      *puVar2 = puVar2 + 0x61a;
      puVar2[0x61b] = &DAT_803b15b0 + iVar6 * 0x61a;
    }
    *(char *)((int)puVar2 + 0x1871) = (char)(iVar6 + 1);
    puVar1 = (undefined4 *)0x0;
    *(undefined *)(puVar2 + 0x61c) = 0;
    puVar3[0x10] = 0xffff;
    puVar2 = puVar2 + 0xc34;
    iVar6 = iVar6 + 2;
    puVar3[0x11] = 0xffff;
    puVar3[0x12] = 0xffff;
    puVar3[0x13] = 0xffff;
    puVar3[0x14] = 0xffff;
    puVar3[0x15] = 0xffff;
    puVar3[0x16] = 0xffff;
    puVar3[0x17] = 0xffff;
    puVar3[0x18] = 0xffff;
    puVar3[0x19] = 0xffff;
    puVar3[0x1a] = 0xffff;
    puVar3[0x1b] = 0xffff;
    puVar3[0x1c] = 0xffff;
    puVar3[0x1d] = 0xffff;
    puVar3[0x1e] = 0xffff;
    puVar3[0x1f] = 0xffff;
    puVar3 = puVar3 + 0x20;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  (&DAT_803afd48)[iVar6 * 0x61a] = 0;
  iVar7 = 0x20;
  iVar6 = 0;
  DAT_803dee9c = &DAT_803b01b0;
  do {
    puVar4[1] = puVar1;
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = puVar4;
    }
    puVar4[6] = puVar4;
    puVar2 = puVar4 + 5;
    if (puVar4 != (undefined4 *)0x0) {
      *puVar4 = puVar2;
    }
    puVar4[0xb] = puVar2;
    puVar1 = puVar4 + 10;
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = puVar1;
    }
    puVar4[0x10] = puVar1;
    puVar2 = puVar4 + 0xf;
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = puVar2;
    }
    puVar4[0x15] = puVar2;
    puVar1 = puVar4 + 0x14;
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = puVar1;
    }
    puVar4[0x1a] = puVar1;
    puVar2 = puVar4 + 0x19;
    if (puVar1 != (undefined4 *)0x0) {
      *puVar1 = puVar2;
    }
    puVar4[0x1f] = puVar2;
    puVar5 = puVar4 + 0x1e;
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = puVar5;
    }
    puVar4[0x24] = puVar5;
    puVar1 = puVar4 + 0x23;
    if (puVar5 != (undefined4 *)0x0) {
      *puVar5 = puVar1;
    }
    puVar4 = puVar4 + 0x28;
    iVar6 = iVar6 + 7;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  *puVar1 = 0;
  DAT_803deea8 = 0;
  return iVar6;
}

