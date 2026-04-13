// Function: FUN_80291620
// Entry: 80291620
// Size: 544 bytes

char * FUN_80291620(uint param_1,int param_2,char *param_3)

{
  bool bVar1;
  uint in_r0;
  char *pcVar2;
  char *pcVar3;
  int iVar4;
  int iVar5;
  char cVar6;
  
  *(undefined *)(param_2 + -1) = 0;
  pcVar2 = (char *)(param_2 + -1);
  bVar1 = false;
  iVar4 = 0;
  if (((param_1 == 0) && (*(int *)(param_3 + 0xc) == 0)) &&
     ((param_3[3] == '\0' || (param_3[5] != 'o')))) {
    return pcVar2;
  }
  switch(param_3[5]) {
  case 'X':
  case 'x':
    in_r0 = 0x10;
    param_3[1] = '\0';
    break;
  case 'd':
  case 'i':
    in_r0 = 10;
    if ((int)param_1 < 0) {
      param_1 = -param_1;
      bVar1 = true;
    }
    break;
  case 'o':
    in_r0 = 8;
    param_3[1] = '\0';
    break;
  case 'u':
    in_r0 = 10;
    param_3[1] = '\0';
  }
  do {
    iVar5 = iVar4;
    pcVar3 = pcVar2;
    iVar4 = param_1 - (param_1 / in_r0) * in_r0;
    param_1 = param_1 / in_r0;
    cVar6 = (char)iVar4;
    if (iVar4 < 10) {
      cVar6 = cVar6 + '0';
    }
    else if (param_3[5] == 'x') {
      cVar6 = cVar6 + 'W';
    }
    else {
      cVar6 = cVar6 + '7';
    }
    pcVar3[-1] = cVar6;
    pcVar2 = pcVar3 + -1;
    iVar4 = iVar5 + 1;
  } while (param_1 != 0);
  if (((in_r0 == 8) && (param_3[3] != '\0')) && (*pcVar2 != '0')) {
    iVar4 = iVar5 + 2;
    pcVar2 = pcVar3 + -2;
    *pcVar2 = '0';
  }
  if (*param_3 == '\x02') {
    *(undefined4 *)(param_3 + 0xc) = *(undefined4 *)(param_3 + 8);
    if ((bVar1) || (param_3[1] != '\0')) {
      *(int *)(param_3 + 0xc) = *(int *)(param_3 + 0xc) + -1;
    }
    if ((in_r0 == 0x10) && (param_3[3] != '\0')) {
      *(int *)(param_3 + 0xc) = *(int *)(param_3 + 0xc) + -2;
    }
  }
  if (0x1fd < *(int *)(param_3 + 0xc) + (param_2 - (int)pcVar2)) {
    return (char *)0x0;
  }
  for (; iVar4 < *(int *)(param_3 + 0xc); iVar4 = iVar4 + 1) {
    pcVar2 = pcVar2 + -1;
    *pcVar2 = '0';
  }
  if ((in_r0 == 0x10) && (param_3[3] != '\0')) {
    pcVar2[-1] = param_3[5];
    pcVar2 = pcVar2 + -2;
    *pcVar2 = '0';
  }
  if (bVar1) {
    pcVar2 = pcVar2 + -1;
    *pcVar2 = '-';
  }
  else if (param_3[1] == '\x01') {
    pcVar2 = pcVar2 + -1;
    *pcVar2 = '+';
  }
  else if (param_3[1] == '\x02') {
    pcVar2 = pcVar2 + -1;
    *pcVar2 = ' ';
  }
  return pcVar2;
}

