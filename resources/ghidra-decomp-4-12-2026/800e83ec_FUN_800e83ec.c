// Function: FUN_800e83ec
// Entry: 800e83ec
// Size: 520 bytes

void FUN_800e83ec(int param_1)

{
  uint uVar1;
  int iVar2;
  undefined1 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    return;
  }
  if (DAT_803de100 != '\0') {
    return;
  }
  iVar4 = 0;
  puVar3 = &DAT_803a3f08;
  iVar6 = 7;
  do {
    iVar2 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14);
    iVar5 = iVar4;
    if ((((((iVar2 == *(int *)(puVar3 + 0x168)) ||
           (iVar5 = iVar4 + 1, iVar2 == *(int *)(puVar3 + 0x178))) ||
          (iVar5 = iVar4 + 2, iVar2 == *(int *)(puVar3 + 0x188))) ||
         ((iVar5 = iVar4 + 3, iVar2 == *(int *)(puVar3 + 0x198) ||
          (iVar5 = iVar4 + 4, iVar2 == *(int *)(puVar3 + 0x1a8))))) ||
        ((iVar5 = iVar4 + 5, iVar2 == *(int *)(puVar3 + 0x1b8) ||
         ((iVar5 = iVar4 + 6, iVar2 == *(int *)(puVar3 + 0x1c8) ||
          (iVar5 = iVar4 + 7, iVar2 == *(int *)(puVar3 + 0x1d8))))))) ||
       (iVar5 = iVar4 + 8, iVar2 == *(int *)(puVar3 + 0x1e8))) break;
    puVar3 = puVar3 + 0x90;
    iVar4 = iVar4 + 9;
    iVar6 = iVar6 + -1;
    iVar5 = iVar4;
  } while (iVar6 != 0);
  if (iVar5 == 0x3f) {
    return;
  }
  puVar3 = &DAT_803a3f08 + iVar5 * 0x10;
  uVar1 = 0x3e - iVar5;
  if (iVar5 < 0x3e) {
    uVar7 = uVar1 >> 2;
    if (uVar7 != 0) {
      do {
        *(undefined4 *)(puVar3 + 0x168) = *(undefined4 *)(puVar3 + 0x178);
        *(undefined4 *)(puVar3 + 0x16c) = *(undefined4 *)(puVar3 + 0x17c);
        *(undefined4 *)(puVar3 + 0x170) = *(undefined4 *)(puVar3 + 0x180);
        *(undefined4 *)(puVar3 + 0x174) = *(undefined4 *)(puVar3 + 0x184);
        *(undefined4 *)(puVar3 + 0x178) = *(undefined4 *)(puVar3 + 0x188);
        *(undefined4 *)(puVar3 + 0x17c) = *(undefined4 *)(puVar3 + 0x18c);
        *(undefined4 *)(puVar3 + 0x180) = *(undefined4 *)(puVar3 + 400);
        *(undefined4 *)(puVar3 + 0x184) = *(undefined4 *)(puVar3 + 0x194);
        *(undefined4 *)(puVar3 + 0x188) = *(undefined4 *)(puVar3 + 0x198);
        *(undefined4 *)(puVar3 + 0x18c) = *(undefined4 *)(puVar3 + 0x19c);
        *(undefined4 *)(puVar3 + 400) = *(undefined4 *)(puVar3 + 0x1a0);
        *(undefined4 *)(puVar3 + 0x194) = *(undefined4 *)(puVar3 + 0x1a4);
        *(undefined4 *)(puVar3 + 0x198) = *(undefined4 *)(puVar3 + 0x1a8);
        *(undefined4 *)(puVar3 + 0x19c) = *(undefined4 *)(puVar3 + 0x1ac);
        *(undefined4 *)(puVar3 + 0x1a0) = *(undefined4 *)(puVar3 + 0x1b0);
        *(undefined4 *)(puVar3 + 0x1a4) = *(undefined4 *)(puVar3 + 0x1b4);
        puVar3 = puVar3 + 0x40;
        uVar7 = uVar7 - 1;
      } while (uVar7 != 0);
      uVar1 = uVar1 & 3;
      if (uVar1 == 0) {
        DAT_803c4060 = 0;
        return;
      }
    }
    do {
      *(undefined4 *)(puVar3 + 0x168) = *(undefined4 *)(puVar3 + 0x178);
      *(undefined4 *)(puVar3 + 0x16c) = *(undefined4 *)(puVar3 + 0x17c);
      *(undefined4 *)(puVar3 + 0x170) = *(undefined4 *)(puVar3 + 0x180);
      *(undefined4 *)(puVar3 + 0x174) = *(undefined4 *)(puVar3 + 0x184);
      puVar3 = puVar3 + 0x10;
      uVar1 = uVar1 - 1;
    } while (uVar1 != 0);
  }
  DAT_803c4060 = 0;
  return;
}

