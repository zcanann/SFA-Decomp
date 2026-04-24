// Function: FUN_8026c250
// Entry: 8026c250
// Size: 208 bytes

void FUN_8026c250(void)

{
  int *piVar1;
  uint uVar2;
  int **ppiVar3;
  int **ppiVar4;
  int iVar5;
  
  iVar5 = 0;
  uVar2 = 0;
  do {
    ppiVar4 = *(int ***)(DAT_803de218 + iVar5 + 0xe64);
    while (ppiVar4 != (int **)0x0) {
      ppiVar3 = (int **)*ppiVar4;
      FUN_80271ac0(ppiVar4[2]);
      piVar1 = *ppiVar4;
      *(int **)(iVar5 + DAT_803de218 + 0xe64) = piVar1;
      if (piVar1 != (int *)0x0) {
        *(undefined4 *)(*(int *)(iVar5 + DAT_803de218 + 0xe64) + 4) = 0;
      }
      piVar1 = *(int **)(DAT_803de218 + 0xe6c);
      *ppiVar4 = piVar1;
      if (piVar1 != (int *)0x0) {
        *(int ***)(*(int *)(DAT_803de218 + 0xe6c) + 4) = ppiVar4;
      }
      *(int ***)(DAT_803de218 + 0xe6c) = ppiVar4;
      ppiVar4 = ppiVar3;
    }
    uVar2 = uVar2 + 1;
    iVar5 = iVar5 + 4;
  } while (uVar2 < 2);
  return;
}

