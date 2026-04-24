// Function: FUN_8026bf54
// Entry: 8026bf54
// Size: 220 bytes

void FUN_8026bf54(int param_1)

{
  int **ppiVar1;
  int **ppiVar2;
  
  ppiVar1 = *(int ***)(param_1 + 0xe64);
  if (*(int ***)(param_1 + 0xe64) != (int **)0x0) {
    do {
      ppiVar2 = ppiVar1;
      ppiVar1 = (int **)*ppiVar2;
    } while ((int **)*ppiVar2 != (int **)0x0);
    if (DAT_803de21c != (int *)0x0) {
      *ppiVar2 = DAT_803de21c;
      DAT_803de21c[1] = (int)ppiVar2;
    }
    DAT_803de21c = *(int **)(param_1 + 0xe64);
    *(undefined4 *)(param_1 + 0xe64) = 0;
  }
  ppiVar1 = *(int ***)(param_1 + 0xe68);
  if (*(int ***)(param_1 + 0xe68) != (int **)0x0) {
    do {
      ppiVar2 = ppiVar1;
      ppiVar1 = (int **)*ppiVar2;
    } while ((int **)*ppiVar2 != (int **)0x0);
    if (DAT_803de21c != (int *)0x0) {
      *ppiVar2 = DAT_803de21c;
      DAT_803de21c[1] = (int)ppiVar2;
    }
    DAT_803de21c = *(int **)(param_1 + 0xe68);
    *(undefined4 *)(param_1 + 0xe68) = 0;
  }
  ppiVar1 = *(int ***)(param_1 + 0xe6c);
  if (*(int ***)(param_1 + 0xe6c) != (int **)0x0) {
    do {
      ppiVar2 = ppiVar1;
      ppiVar1 = (int **)*ppiVar2;
    } while ((int **)*ppiVar2 != (int **)0x0);
    if (DAT_803de21c != (int *)0x0) {
      *ppiVar2 = DAT_803de21c;
      DAT_803de21c[1] = (int)ppiVar2;
    }
    DAT_803de21c = *(int **)(param_1 + 0xe6c);
    *(undefined4 *)(param_1 + 0xe6c) = 0;
    return;
  }
  return;
}

