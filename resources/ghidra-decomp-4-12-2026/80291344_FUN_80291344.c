// Function: FUN_80291344
// Entry: 80291344
// Size: 732 bytes

char * FUN_80291344(uint param_1,int param_2,int param_3,char *param_4)

{
  bool bVar1;
  char cVar2;
  int iVar3;
  int iVar4;
  char *pcVar5;
  char *pcVar6;
  uint unaff_r28;
  int unaff_r29;
  uint uVar7;
  undefined8 uVar8;
  longlong lVar9;
  
  pcVar5 = (char *)(param_3 + -1);
  bVar1 = false;
  iVar3 = 0;
  *(undefined *)(param_3 + -1) = 0;
  if (((param_2 != 0 || param_1 != 0) || (*(int *)(param_4 + 0xc) != 0)) ||
     ((param_4[3] != '\0' && (param_4[5] == 'o')))) {
    lVar9 = CONCAT44(param_1,param_2);
    switch(param_4[5]) {
    case 'X':
    case 'x':
      unaff_r28 = 0x10;
      param_4[1] = '\0';
      unaff_r29 = 0;
      lVar9 = CONCAT44(param_1,param_2);
      break;
    case 'd':
    case 'i':
      unaff_r28 = 10;
      unaff_r29 = 0;
      lVar9 = CONCAT44(param_1,param_2);
      if ((param_1 ^ 0x80000000) < 0x80000000) {
        bVar1 = true;
        lVar9 = CONCAT44(-((param_2 != 0) + param_1),-param_2);
      }
      break;
    case 'o':
      unaff_r28 = 8;
      param_4[1] = '\0';
      unaff_r29 = 0;
      lVar9 = CONCAT44(param_1,param_2);
      break;
    case 'u':
      unaff_r28 = 10;
      param_4[1] = '\0';
      unaff_r29 = 0;
      lVar9 = CONCAT44(param_1,param_2);
    }
    do {
      pcVar6 = pcVar5;
      iVar4 = iVar3;
      uVar7 = (uint)((ulonglong)lVar9 >> 0x20);
      uVar8 = FUN_80286ac8(uVar7,(uint)lVar9,unaff_r29,unaff_r28);
      lVar9 = FUN_802868a4(uVar7,(uint)lVar9,unaff_r29,unaff_r28);
      cVar2 = (char)uVar8;
      if ((int)uVar8 < 10) {
        cVar2 = cVar2 + '0';
      }
      else if (param_4[5] == 'x') {
        cVar2 = cVar2 + 'W';
      }
      else {
        cVar2 = cVar2 + '7';
      }
      pcVar5 = pcVar6 + -1;
      *pcVar5 = cVar2;
      iVar3 = iVar4 + 1;
    } while (lVar9 != 0);
    if (((unaff_r28 == 8 && unaff_r29 == 0) && (param_4[3] != '\0')) && (*pcVar5 != '0')) {
      iVar3 = iVar4 + 2;
      pcVar5 = pcVar6 + -2;
      *pcVar5 = '0';
    }
    if (*param_4 == '\x02') {
      *(undefined4 *)(param_4 + 0xc) = *(undefined4 *)(param_4 + 8);
      if ((bVar1) || (param_4[1] != '\0')) {
        *(int *)(param_4 + 0xc) = *(int *)(param_4 + 0xc) + -1;
      }
      if ((unaff_r28 == 0x10 && unaff_r29 == 0) && (param_4[3] != '\0')) {
        *(int *)(param_4 + 0xc) = *(int *)(param_4 + 0xc) + -2;
      }
    }
    if (*(int *)(param_4 + 0xc) + (param_3 - (int)pcVar5) < 0x1fe) {
      for (; iVar3 < *(int *)(param_4 + 0xc); iVar3 = iVar3 + 1) {
        pcVar5 = pcVar5 + -1;
        *pcVar5 = '0';
      }
      if ((unaff_r28 == 0x10 && unaff_r29 == 0) && (param_4[3] != '\0')) {
        pcVar5[-1] = param_4[5];
        pcVar5 = pcVar5 + -2;
        *pcVar5 = '0';
      }
      if (bVar1) {
        pcVar5 = pcVar5 + -1;
        *pcVar5 = '-';
      }
      else if (param_4[1] == '\x01') {
        pcVar5 = pcVar5 + -1;
        *pcVar5 = '+';
      }
      else if (param_4[1] == '\x02') {
        pcVar5 = pcVar5 + -1;
        *pcVar5 = ' ';
      }
    }
    else {
      pcVar5 = (char *)0x0;
    }
  }
  return pcVar5;
}

