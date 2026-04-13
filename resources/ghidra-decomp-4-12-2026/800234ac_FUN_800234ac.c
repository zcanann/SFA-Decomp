// Function: FUN_800234ac
// Entry: 800234ac
// Size: 260 bytes

void FUN_800234ac(uint param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 *puVar3;
  int iVar4;
  uint *puVar5;
  
  DAT_803dd7b4 = FUN_802473cc();
  iVar2 = 0;
  puVar3 = &DAT_80341300;
  for (uVar1 = (uint)DAT_803dd7c2; uVar1 != 0; uVar1 = uVar1 - 1) {
    if (((uint)puVar3[2] < param_1) && (param_1 < (uint)(puVar3[2] + puVar3[3]))) goto LAB_80023514;
    puVar3 = puVar3 + 5;
    iVar2 = iVar2 + 1;
  }
  iVar2 = -1;
LAB_80023514:
  if (iVar2 != -1) {
    iVar4 = 0;
    do {
      puVar5 = (uint *)((&DAT_80341308)[iVar2 * 5] + iVar4 * 0x1c);
      if (*puVar5 == param_1) {
        if ((*(short *)(puVar5 + 2) != 1) && (*(short *)(puVar5 + 2) != 4)) {
          FUN_8007d858();
          return;
        }
        FUN_800231f8();
        return;
      }
      iVar4 = (int)*(short *)(puVar5 + 3);
    } while (iVar4 != -1);
  }
  FUN_8007d858();
  return;
}

