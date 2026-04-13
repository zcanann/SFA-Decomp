// Function: FUN_8024e11c
// Entry: 8024e11c
// Size: 304 bytes

void FUN_8024e11c(char *param_1,char *param_2,char param_3,char param_4,char param_5)

{
  int iVar1;
  char cVar2;
  int iVar3;
  char cVar4;
  int iVar5;
  int iVar6;
  
  iVar1 = (int)*param_1;
  iVar6 = (int)*param_2;
  if (iVar1 < 0) {
    cVar2 = -1;
    iVar1 = -iVar1;
  }
  else {
    cVar2 = '\x01';
  }
  if (iVar6 < 0) {
    cVar4 = -1;
    iVar6 = -iVar6;
  }
  else {
    cVar4 = '\x01';
  }
  iVar3 = (int)param_5;
  if (iVar3 < iVar1) {
    iVar1 = iVar1 - iVar3;
  }
  else {
    iVar1 = 0;
  }
  if (iVar3 < iVar6) {
    iVar6 = iVar6 - iVar3;
  }
  else {
    iVar6 = 0;
  }
  if ((iVar1 == 0) && (iVar6 == 0)) {
    *param_2 = '\0';
    *param_1 = '\0';
    return;
  }
  iVar3 = (int)param_4;
  if (iVar3 * iVar1 < iVar3 * iVar6) {
    iVar5 = iVar3 * param_3;
    iVar3 = iVar3 * iVar6 + iVar1 * (param_3 - iVar3);
    if (iVar5 < iVar3) {
      iVar1 = (int)(char)((iVar1 * iVar5) / iVar3);
      iVar6 = (int)(char)((iVar6 * iVar5) / iVar3);
    }
  }
  else {
    iVar5 = iVar3 * param_3;
    iVar3 = iVar3 * iVar1 + iVar6 * (param_3 - iVar3);
    if (iVar5 < iVar3) {
      iVar1 = (int)(char)((iVar1 * iVar5) / iVar3);
      iVar6 = (int)(char)((iVar6 * iVar5) / iVar3);
    }
  }
  *param_1 = cVar2 * (char)iVar1;
  *param_2 = cVar4 * (char)iVar6;
  return;
}

