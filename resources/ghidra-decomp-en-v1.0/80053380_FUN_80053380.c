// Function: FUN_80053380
// Entry: 80053380
// Size: 204 bytes

void FUN_80053380(int *param_1)

{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (*param_1 != 0) {
    iVar2 = 0;
    piVar1 = &DAT_8037e000;
    iVar3 = 6;
    do {
      if ((*(short *)(*piVar1 + 0xe) != 0) && (*piVar1 == *param_1)) {
        *(short *)((&DAT_8037e000)[iVar2 * 7] + 0xe) =
             *(short *)((&DAT_8037e000)[iVar2 * 7] + 0xe) + -1;
        break;
      }
      piVar1 = piVar1 + 7;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (param_1[1] == 0) {
    return;
  }
  iVar2 = 0;
  piVar1 = &DAT_8037e000;
  iVar3 = 6;
  while ((*(short *)(*piVar1 + 0xe) == 0 || (*piVar1 != param_1[1]))) {
    piVar1 = piVar1 + 7;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return;
    }
  }
  *(short *)((&DAT_8037e000)[iVar2 * 7] + 0xe) = *(short *)((&DAT_8037e000)[iVar2 * 7] + 0xe) + -1;
  return;
}

