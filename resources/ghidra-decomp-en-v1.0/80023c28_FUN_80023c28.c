// Function: FUN_80023c28
// Entry: 80023c28
// Size: 148 bytes

uint FUN_80023c28(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  uint *puVar4;
  int iVar5;
  
  iVar5 = 0;
  puVar3 = &DAT_803406a0;
  for (uVar1 = (uint)DAT_803dcb42; uVar1 != 0; uVar1 = uVar1 - 1) {
    if (((uint)puVar3[2] < param_1) && (param_1 < (uint)(puVar3[2] + puVar3[3]))) goto LAB_80023c74;
    puVar3 = puVar3 + 5;
    iVar5 = iVar5 + 1;
  }
  iVar5 = -1;
LAB_80023c74:
  iVar2 = 0;
  do {
    puVar4 = (uint *)((&DAT_803406a8)[iVar5 * 5] + iVar2 * 0x1c);
    if (*puVar4 == param_1) {
      return puVar4[1];
    }
    iVar2 = (int)*(short *)(puVar4 + 3);
  } while (iVar2 != -1);
  return 0xffffffff;
}

