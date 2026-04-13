// Function: FUN_800e85f4
// Entry: 800e85f4
// Size: 360 bytes

void FUN_800e85f4(int param_1)

{
  int iVar1;
  undefined1 *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  if ((*(ushort *)(param_1 + 6) & 0x2000) != 0) {
    return;
  }
  if (DAT_803de100 != '\0') {
    return;
  }
  iVar3 = 0;
  puVar2 = &DAT_803a3f08;
  iVar5 = 9;
  while ((iVar4 = iVar3, *(int *)(puVar2 + 0x168) != 0 &&
         (iVar1 = *(int *)(*(int *)(param_1 + 0x4c) + 0x14), iVar1 != *(int *)(puVar2 + 0x168)))) {
    iVar4 = iVar3 + 1;
    if ((*(int *)(puVar2 + 0x178) == 0) || (iVar1 == *(int *)(puVar2 + 0x178))) break;
    iVar4 = iVar3 + 2;
    if ((*(int *)(puVar2 + 0x188) == 0) || (iVar1 == *(int *)(puVar2 + 0x188))) break;
    iVar4 = iVar3 + 3;
    if ((*(int *)(puVar2 + 0x198) == 0) || (iVar1 == *(int *)(puVar2 + 0x198))) break;
    iVar4 = iVar3 + 4;
    if ((*(int *)(puVar2 + 0x1a8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1a8))) break;
    iVar4 = iVar3 + 5;
    if ((*(int *)(puVar2 + 0x1b8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1b8))) break;
    iVar4 = iVar3 + 6;
    if ((*(int *)(puVar2 + 0x1c8) == 0) || (iVar1 == *(int *)(puVar2 + 0x1c8))) break;
    puVar2 = puVar2 + 0x70;
    iVar3 = iVar3 + 7;
    iVar5 = iVar5 + -1;
    iVar4 = iVar3;
    if (iVar5 == 0) break;
  }
  if (iVar4 == 0x3f) {
    return;
  }
  (&DAT_803a4070)[iVar4 * 4] = *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0x14);
  (&DAT_803a4074)[iVar4 * 4] = *(undefined4 *)(param_1 + 0xc);
  (&DAT_803a4078)[iVar4 * 4] = *(undefined4 *)(param_1 + 0x10);
  (&DAT_803a407c)[iVar4 * 4] = *(undefined4 *)(param_1 + 0x14);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 8) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0xc) = *(undefined4 *)(param_1 + 0x10);
  *(undefined4 *)(*(int *)(param_1 + 0x4c) + 0x10) = *(undefined4 *)(param_1 + 0x14);
  return;
}

