// Function: FUN_8024900c
// Entry: 8024900c
// Size: 756 bytes

uint FUN_8024900c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9)

{
  char cVar1;
  char cVar2;
  bool bVar3;
  bool bVar4;
  uint uVar5;
  uint *puVar6;
  uint uVar7;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  char *pcVar8;
  char *pcVar9;
  char *pcVar10;
  char *unaff_r24;
  uint uVar11;
  char *pcVar12;
  int iVar13;
  
  pcVar10 = param_9;
  uVar11 = DAT_803deb78;
LAB_80249030:
  while( true ) {
    while( true ) {
      cVar1 = *pcVar10;
      if (cVar1 == '\0') {
        return uVar11;
      }
      if (cVar1 != '/') break;
      uVar11 = 0;
      pcVar10 = pcVar10 + 1;
    }
    if (cVar1 != '.') break;
    cVar1 = pcVar10[1];
    if (cVar1 == '.') {
      if (pcVar10[2] != '/') {
        if (pcVar10[2] == '\0') {
          return *(uint *)(DAT_803deb6c + uVar11 * 0xc + 4);
        }
        break;
      }
      uVar11 = *(uint *)(DAT_803deb6c + uVar11 * 0xc + 4);
      pcVar10 = pcVar10 + 3;
    }
    else {
      if (cVar1 != '/') {
        if (cVar1 == '\0') {
          return uVar11;
        }
        break;
      }
      pcVar10 = pcVar10 + 2;
    }
  }
  pcVar12 = pcVar10;
  if (DAT_803deb7c == 0) {
    bVar3 = false;
    bVar4 = false;
LAB_80249134:
    cVar1 = *pcVar12;
    if ((cVar1 == '\0') || (cVar1 == '/')) goto LAB_8024914c;
    if (cVar1 == '.') {
      if ((8 < (int)pcVar12 - (int)pcVar10) || (bVar3)) {
        bVar4 = true;
LAB_8024914c:
        if ((bVar3) && (3 < (int)pcVar12 - (int)unaff_r24)) {
          bVar4 = true;
        }
        if (bVar4) {
          param_1 = FUN_80242fc0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                 &DAT_803dd1c8,0x178,s_DVDConvertEntrynumToPath_possibl_8032e488,
                                 param_9,in_r7,in_r8,in_r9,in_r10);
        }
        goto LAB_802491ac;
      }
      unaff_r24 = pcVar12 + 1;
      bVar3 = true;
    }
    else if (cVar1 == ' ') {
      bVar4 = true;
    }
    pcVar12 = pcVar12 + 1;
    goto LAB_80249134;
  }
  for (; (*pcVar12 != '\0' && (*pcVar12 != '/')); pcVar12 = pcVar12 + 1) {
  }
LAB_802491ac:
  cVar1 = *pcVar12;
  iVar13 = uVar11 * 0xc;
  uVar11 = uVar11 + 1;
LAB_802492b4:
  if (*(uint *)(iVar13 + DAT_803deb6c + 8) <= uVar11) {
    return 0xffffffff;
  }
  uVar7 = *(uint *)(DAT_803deb6c + uVar11 * 0xc);
  if (((uVar7 & 0xff000000) != 0) || (cVar1 == '\0')) {
    pcVar8 = (char *)(DAT_803deb70 + (uVar7 & 0xffffff));
    pcVar9 = pcVar10;
    do {
      if (*pcVar8 == '\0') {
        if ((*pcVar9 == '/') || (*pcVar9 == '\0')) {
          bVar3 = true;
        }
        else {
          bVar3 = false;
        }
        goto LAB_80249274;
      }
      cVar2 = *pcVar8;
      pcVar8 = pcVar8 + 1;
      uVar7 = FUN_80294dbc((int)cVar2);
      cVar2 = *pcVar9;
      pcVar9 = pcVar9 + 1;
      uVar5 = FUN_80294dbc((int)cVar2);
    } while (uVar5 == uVar7);
    bVar3 = false;
LAB_80249274:
    if (bVar3) goto LAB_802492d0;
  }
  puVar6 = (uint *)(DAT_803deb6c + uVar11 * 0xc);
  if ((*puVar6 & 0xff000000) == 0) {
    uVar11 = uVar11 + 1;
  }
  else {
    uVar11 = puVar6[2];
  }
  goto LAB_802492b4;
LAB_802492d0:
  if (cVar1 == '\0') {
    return uVar11;
  }
  pcVar10 = pcVar12 + 1;
  goto LAB_80249030;
}

