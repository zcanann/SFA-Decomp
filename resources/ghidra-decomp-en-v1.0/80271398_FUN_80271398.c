// Function: FUN_80271398
// Entry: 80271398
// Size: 148 bytes

void FUN_80271398(int *param_1,code *param_2)

{
  byte *pbVar1;
  int **ppiVar2;
  int *piVar3;
  
  ppiVar2 = (int **)*param_1;
  while (ppiVar2 != (int **)0x0) {
    piVar3 = *ppiVar2;
    *(undefined *)((int)ppiVar2 + 9) = 0xff;
    pbVar1 = (byte *)(ppiVar2 + 2);
    ppiVar2 = (int **)piVar3;
    if (*(char *)(DAT_803de268 + (uint)*pbVar1 * 0x404 + 0x11c) == '\0') {
      (*param_2)();
    }
  }
  *param_1 = 0;
  return;
}

