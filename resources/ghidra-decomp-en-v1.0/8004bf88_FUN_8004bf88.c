// Function: FUN_8004bf88
// Entry: 8004bf88
// Size: 604 bytes

void FUN_8004bf88(undefined4 *param_1,char param_2,char param_3,int *param_4,int *param_5)

{
  char cVar1;
  bool bVar2;
  bool bVar3;
  undefined4 local_8 [2];
  
  bVar2 = false;
  bVar3 = false;
  if (param_2 == '\0') {
    bVar2 = true;
  }
  else {
    cVar1 = *(char *)param_1;
    if ((cVar1 == *(char *)((int)param_1 + 1)) && (cVar1 == *(char *)((int)param_1 + 2))) {
      if (cVar1 == -1) {
        *param_4 = 0;
        bVar2 = true;
      }
      else if (cVar1 == -0x20) {
        *param_4 = 1;
        bVar2 = true;
      }
      else if (cVar1 == -0x40) {
        *param_4 = 2;
        bVar2 = true;
      }
      else if (cVar1 == -0x60) {
        *param_4 = 3;
        bVar2 = true;
      }
      else if (cVar1 == -0x80) {
        *param_4 = 4;
        bVar2 = true;
      }
      else if (cVar1 == '`') {
        *param_4 = 5;
        bVar2 = true;
      }
      else if (cVar1 == '@') {
        *param_4 = 6;
        bVar2 = true;
      }
      else if (cVar1 == ' ') {
        *param_4 = 7;
        bVar2 = true;
      }
    }
    if (!bVar2) {
      *param_4 = DAT_803dcd70;
    }
  }
  if (param_3 == '\0') {
    bVar3 = true;
  }
  else {
    cVar1 = *(char *)((int)param_1 + 3);
    if (cVar1 == -1) {
      *param_5 = 0;
      bVar3 = true;
    }
    else if (cVar1 == -0x20) {
      *param_5 = 1;
      bVar3 = true;
    }
    else if (cVar1 == -0x40) {
      *param_5 = 2;
      bVar3 = true;
    }
    else if (cVar1 == -0x60) {
      *param_5 = 3;
      bVar3 = true;
    }
    else if (cVar1 == -0x80) {
      *param_5 = 4;
      bVar3 = true;
    }
    else if (cVar1 == '`') {
      *param_5 = 5;
      bVar3 = true;
    }
    else if (cVar1 == '@') {
      *param_5 = 6;
      bVar3 = true;
    }
    else if (cVar1 == ' ') {
      *param_5 = 7;
      bVar3 = true;
    }
    if (!bVar3) {
      *param_5 = DAT_803dcd6c;
    }
  }
  if ((!bVar2) || (!bVar3)) {
    local_8[0] = *param_1;
    FUN_8025bdac(DAT_803dcd74,local_8);
    DAT_803dcd74 = DAT_803dcd74 + 1;
    DAT_803dcd70 = DAT_803dcd70 + 1;
    DAT_803dcd6c = DAT_803dcd6c + 1;
  }
  return;
}

