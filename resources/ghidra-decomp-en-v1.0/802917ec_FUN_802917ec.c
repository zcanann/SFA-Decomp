// Function: FUN_802917ec
// Entry: 802917ec
// Size: 184 bytes

void FUN_802917ec(int *param_1,int *param_2)

{
  char cVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  
  uVar2 = (uint)param_2 & 3;
  if (((uint)param_1 & 3) == uVar2) {
    if (uVar2 != 0) {
      cVar1 = *(char *)param_2;
      *(char *)param_1 = cVar1;
      if (cVar1 == '\0') {
        return;
      }
      for (iVar4 = 3 - uVar2; iVar4 != 0; iVar4 = iVar4 + -1) {
        param_2 = (int *)((int)param_2 + 1);
        cVar1 = *(char *)param_2;
        param_1 = (int *)((int)param_1 + 1);
        *(char *)param_1 = cVar1;
        if (cVar1 == '\0') {
          return;
        }
      }
      param_1 = (int *)((int)param_1 + 1);
      param_2 = (int *)((int)param_2 + 1);
    }
    iVar4 = *param_2;
    if ((iVar4 + 0xfefefeffU & 0x80808080) == 0) {
      piVar3 = param_1 + -1;
      do {
        param_1 = piVar3;
        piVar3 = param_1 + 1;
        *piVar3 = iVar4;
        param_2 = param_2 + 1;
        iVar4 = *param_2;
      } while ((iVar4 + 0xfefefeffU & 0x80808080) == 0);
      param_1 = param_1 + 2;
    }
  }
  cVar1 = *(char *)param_2;
  *(char *)param_1 = cVar1;
  if (cVar1 != '\0') {
    do {
      param_2 = (int *)((int)param_2 + 1);
      cVar1 = *(char *)param_2;
      param_1 = (int *)((int)param_1 + 1);
      *(char *)param_1 = cVar1;
    } while (cVar1 != '\0');
    return;
  }
  return;
}

