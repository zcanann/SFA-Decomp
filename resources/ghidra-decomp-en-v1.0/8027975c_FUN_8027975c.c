// Function: FUN_8027975c
// Entry: 8027975c
// Size: 1084 bytes

uint FUN_8027975c(byte param_1,byte param_2,short param_3,char param_4)

{
  byte bVar1;
  ushort uVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  
  if (DAT_803de270 != '\0') {
    return 0xffffffff;
  }
  if (param_4 == '\0') {
    bVar3 = false;
    if ((DAT_803bd361 <= DAT_803de2fe) && (DAT_803bd361 < DAT_803bd360)) {
      bVar3 = true;
    }
    if (param_2 < DAT_803bd361) goto LAB_802797fc;
  }
  else {
    bVar3 = false;
    if ((DAT_803bd362 <= DAT_803de2ff) && (DAT_803bd362 < DAT_803bd360)) {
      bVar3 = true;
    }
    if (param_2 < DAT_803bd362) {
LAB_802797fc:
      iVar9 = 0;
      uVar7 = 0xffffffff;
      uVar2 = DAT_803de2fc;
      while (((uVar2 != 0xffff && (uVar2 <= param_1)) && (uVar7 == 0xffffffff))) {
        bVar1 = (&DAT_803cac90)[uVar2];
        while (uVar8 = (uint)bVar1, uVar8 != 0xff) {
          iVar6 = DAT_803de268 + uVar8 * 0x404;
          uVar5 = uVar7;
          if ((((param_3 == *(short *)(iVar6 + 0x100)) &&
               (iVar9 = iVar9 + 1, *(char *)(iVar6 + 0x11c) == '\0')) &&
              ((!bVar3 || (param_4 == *(char *)(iVar6 + 0x11d))))) &&
             ((((*(uint *)(iVar6 + 0x118) & 2) == 0 && (uVar5 = uVar8, uVar7 != 0xffffffff)) &&
              (uVar5 = uVar7,
              *(uint *)(iVar6 + 0x110) < *(uint *)(DAT_803de268 + uVar7 * 0x404 + 0x110))))) {
            uVar5 = uVar8;
          }
          uVar7 = uVar5;
          bVar1 = (&DAT_803cab91)[uVar8 * 4];
        }
        uVar2 = *(ushort *)(&DAT_803cad90 + (uint)uVar2 * 4);
      }
      uVar8 = (uint)param_2;
      if ((int)uVar8 <= iVar9) goto LAB_80279aa4;
      while ((uVar5 = (uint)uVar2, uVar5 != 0xffff && (iVar9 < (int)uVar8))) {
        bVar1 = (&DAT_803cac90)[uVar5];
        while (uVar4 = (uint)bVar1, uVar4 != 0xff) {
          if (param_3 == *(short *)(DAT_803de268 + uVar4 * 0x404 + 0x100)) {
            iVar9 = iVar9 + 1;
          }
          bVar1 = (&DAT_803cab91)[uVar4 * 4];
        }
        uVar2 = *(ushort *)(&DAT_803cad90 + uVar5 * 4);
      }
      if ((int)uVar8 <= iVar9) goto LAB_80279aa4;
    }
  }
  uVar7 = (uint)DAT_803de301;
  uVar8 = 0xffffffff;
  if ((uVar7 == 0xff) || (bVar3)) {
    uVar7 = (uint)DAT_803de2fc;
    if (param_1 < uVar7) {
      return 0xffffffff;
    }
    while (((uVar7 != 0xffff && (uVar7 <= param_1)) && (uVar8 == 0xffffffff))) {
      bVar1 = (&DAT_803cac90)[uVar7];
      while (uVar5 = (uint)bVar1, uVar5 != 0xff) {
        iVar9 = DAT_803de268 + uVar5 * 0x404;
        uVar4 = uVar8;
        if ((((*(char *)(iVar9 + 0x11c) == '\0') &&
             ((!bVar3 || (param_4 == *(char *)(iVar9 + 0x11d))))) &&
            ((*(uint *)(iVar9 + 0x118) & 2) == 0)) &&
           ((uVar4 = uVar5, uVar8 != 0xffffffff &&
            (uVar4 = uVar8,
            *(uint *)(iVar9 + 0x110) < *(uint *)(DAT_803de268 + uVar8 * 0x404 + 0x110))))) {
          uVar4 = uVar5;
        }
        uVar8 = uVar4;
        bVar1 = (&DAT_803cab91)[uVar5 * 4];
      }
      uVar7 = (uint)*(ushort *)(&DAT_803cad90 + uVar7 * 4);
    }
    uVar7 = uVar8;
    if (uVar8 == 0xffffffff) {
      return 0xffffffff;
    }
  }
  if (param_1 < *(byte *)(DAT_803de268 + uVar7 * 0x404 + 0x10c)) {
    return 0xffffffff;
  }
LAB_80279aa4:
  if (uVar7 == 0xffffffff) {
    return 0xffffffff;
  }
  iVar9 = uVar7 * 4;
  if ((&DAT_803cb192)[uVar7 * 2] == 1) {
    if ((byte)(&DAT_803cb190)[iVar9] == 0xff) {
      DAT_803de301 = (&DAT_803cb191)[iVar9];
    }
    else {
      (&DAT_803cb191)[(uint)(byte)(&DAT_803cb190)[iVar9] * 4] = (&DAT_803cb191)[iVar9];
    }
    if ((byte)(&DAT_803cb191)[iVar9] != 0xff) {
      (&DAT_803cb190)[(uint)(byte)(&DAT_803cb191)[iVar9] * 4] = (&DAT_803cb190)[iVar9];
    }
    if (uVar7 == DAT_803de300) {
      DAT_803de300 = (&DAT_803cb190)[iVar9];
    }
    (&DAT_803cb192)[uVar7 * 2] = 0;
  }
  else if (*(char *)(DAT_803de268 + uVar7 * 0x404 + 0x11d) == '\0') {
    DAT_803de2fe = DAT_803de2fe - 1;
  }
  else {
    DAT_803de2ff = DAT_803de2ff - 1;
  }
  if (param_4 == '\0') {
    DAT_803de2fe = DAT_803de2fe + 1;
    return uVar7;
  }
  DAT_803de2ff = DAT_803de2ff + 1;
  return uVar7;
}

