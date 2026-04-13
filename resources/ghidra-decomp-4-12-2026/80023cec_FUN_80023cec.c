// Function: FUN_80023cec
// Entry: 80023cec
// Size: 148 bytes

uint FUN_80023cec(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  uint *puVar4;
  int iVar5;
  
  iVar5 = 0;
  puVar3 = &DAT_80341300;
  for (uVar1 = (uint)DAT_803dd7c2; uVar1 != 0; uVar1 = uVar1 - 1) {
    if (((uint)puVar3[2] < param_1) && (param_1 < (uint)(puVar3[2] + puVar3[3]))) goto LAB_80023d38;
    puVar3 = puVar3 + 5;
    iVar5 = iVar5 + 1;
  }
  iVar5 = -1;
LAB_80023d38:
  iVar2 = 0;
  do {
    puVar4 = (uint *)((&DAT_80341308)[iVar5 * 5] + iVar2 * 0x1c);
    if (*puVar4 == param_1) {
      return puVar4[1];
    }
    iVar2 = (int)*(short *)(puVar4 + 3);
  } while (iVar2 != -1);
  return 0xffffffff;
}

