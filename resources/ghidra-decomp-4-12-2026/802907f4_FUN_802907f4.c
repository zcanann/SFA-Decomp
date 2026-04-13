// Function: FUN_802907f4
// Entry: 802907f4
// Size: 1772 bytes

byte * FUN_802907f4(double param_1,int param_2,int param_3)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  byte *pbVar5;
  int iVar6;
  byte bVar7;
  byte *pbVar8;
  uint uVar9;
  undefined local_48 [2];
  undefined2 local_46;
  char local_44 [2];
  short local_42;
  byte local_40;
  byte local_3f [39];
  
  if (0x1fd < *(int *)(param_3 + 0xc)) {
    return (byte *)0x0;
  }
  local_48[0] = 0;
  local_46 = 0x20;
  FUN_8028e344(param_1,(int)local_48,local_44);
  pbVar8 = local_3f + local_40;
  while ((1 < local_40 && (pbVar8 = pbVar8 + -1, *pbVar8 == 0x30))) {
    local_40 = local_40 - 1;
    local_42 = local_42 + 1;
  }
  if (local_3f[0] == 0x49) {
    if (DOUBLE_803e85d8 <= param_1) {
      pbVar8 = (byte *)(param_2 + -4);
      if (((&DAT_80333248)[*(byte *)(param_3 + 5)] & 0x80) != 0) {
        FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3283);
        return pbVar8;
      }
      FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3287);
      return pbVar8;
    }
    pbVar8 = (byte *)(param_2 + -5);
    if (((&DAT_80333248)[*(byte *)(param_3 + 5)] & 0x80) != 0) {
      FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3279);
      return pbVar8;
    }
    FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c327e);
    return pbVar8;
  }
  if (local_3f[0] < 0x49) {
    if (local_3f[0] == 0x30) {
      local_42 = 0;
    }
  }
  else if (local_3f[0] == 0x4e) {
    if (local_44[0] == '\0') {
      pbVar8 = (byte *)(param_2 + -4);
      if (((&DAT_80333248)[*(byte *)(param_3 + 5)] & 0x80) != 0) {
        FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3295);
        return pbVar8;
      }
      FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3299);
      return pbVar8;
    }
    pbVar8 = (byte *)(param_2 + -5);
    if (((&DAT_80333248)[*(byte *)(param_3 + 5)] & 0x80) != 0) {
      FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c328b);
      return pbVar8;
    }
    FUN_80291f4c((int *)pbVar8,(int *)&DAT_802c3290);
    return pbVar8;
  }
  pbVar8 = (byte *)(param_2 + -1);
  local_42 = (ushort)local_40 + local_42 + -1;
  *(undefined *)(param_2 + -1) = 0;
  bVar7 = *(byte *)(param_3 + 5);
  if (bVar7 == 0x65) goto LAB_80290b30;
  if (bVar7 < 0x65) {
    if (bVar7 != 0x46) {
      if (bVar7 < 0x46) {
        if (bVar7 < 0x45) {
          return pbVar8;
        }
        goto LAB_80290b30;
      }
      if (0x47 < bVar7) {
        return pbVar8;
      }
LAB_80290a78:
      if (*(int *)(param_3 + 0xc) < (int)(uint)local_40) {
        FUN_80290ee0((int)local_44,*(int *)(param_3 + 0xc));
      }
      iVar4 = (int)local_42;
      if ((iVar4 < -4) || (*(int *)(param_3 + 0xc) <= iVar4)) {
        if (*(char *)(param_3 + 3) == '\0') {
          *(uint *)(param_3 + 0xc) = local_40 - 1;
        }
        else {
          *(int *)(param_3 + 0xc) = *(int *)(param_3 + 0xc) + -1;
        }
        if (*(char *)(param_3 + 5) == 'g') {
          *(undefined *)(param_3 + 5) = 0x65;
        }
        else {
          *(undefined *)(param_3 + 5) = 0x45;
        }
LAB_80290b30:
        iVar4 = *(int *)(param_3 + 0xc) + 1;
        if (iVar4 < (int)(uint)local_40) {
          FUN_80290ee0((int)local_44,iVar4);
        }
        iVar4 = (int)local_42;
        bVar7 = 0x2b;
        if (iVar4 < 0) {
          iVar4 = -iVar4;
          bVar7 = 0x2d;
        }
        for (iVar6 = 0; (iVar4 != 0 || (iVar6 < 2)); iVar6 = iVar6 + 1) {
          iVar2 = iVar4 / 10 + (iVar4 >> 0x1f);
          cVar1 = (char)iVar4;
          iVar4 = iVar2 - (iVar2 >> 0x1f);
          pbVar8[-1] = cVar1 + ((char)iVar2 - (char)(iVar2 >> 0x1f)) * -10 + 0x30;
          pbVar8 = pbVar8 + -1;
        }
        pbVar8[-1] = bVar7;
        pbVar8 = pbVar8 + -2;
        *pbVar8 = *(byte *)(param_3 + 5);
        iVar4 = *(int *)(param_3 + 0xc);
        if (0x1fd < iVar4 + (param_2 - (int)pbVar8)) {
          return (byte *)0x0;
        }
        if ((int)(uint)local_40 < iVar4 + 1) {
          iVar4 = (iVar4 + 2) - (uint)local_40;
          while (iVar4 = iVar4 + -1, iVar4 != 0) {
            pbVar8 = pbVar8 + -1;
            *pbVar8 = 0x30;
          }
        }
        uVar3 = (uint)local_40;
        pbVar5 = local_3f + uVar3;
        while (uVar3 = uVar3 - 1, uVar3 != 0) {
          pbVar5 = pbVar5 + -1;
          pbVar8 = pbVar8 + -1;
          *pbVar8 = *pbVar5;
        }
        if ((*(int *)(param_3 + 0xc) != 0) || (*(char *)(param_3 + 3) != '\0')) {
          pbVar8 = pbVar8 + -1;
          *pbVar8 = 0x2e;
        }
        pbVar8[-1] = local_3f[0];
        if (local_44[0] != '\0') {
          pbVar8[-2] = 0x2d;
          return pbVar8 + -2;
        }
        if (*(char *)(param_3 + 1) == '\x01') {
          pbVar8[-2] = 0x2b;
          return pbVar8 + -2;
        }
        if (*(char *)(param_3 + 1) != '\x02') {
          return pbVar8 + -1;
        }
        pbVar8[-2] = 0x20;
        return pbVar8 + -2;
      }
      if (*(char *)(param_3 + 3) == '\0') {
        iVar4 = (uint)local_40 - (iVar4 + 1);
        *(int *)(param_3 + 0xc) = iVar4;
        if (iVar4 < 0) {
          *(undefined4 *)(param_3 + 0xc) = 0;
        }
      }
      else {
        *(int *)(param_3 + 0xc) = *(int *)(param_3 + 0xc) - (iVar4 + 1);
      }
    }
  }
  else {
    if (bVar7 == 0x67) goto LAB_80290a78;
    if (0x66 < bVar7) {
      return pbVar8;
    }
  }
  iVar4 = ((uint)local_40 - (int)local_42) + -1;
  if (iVar4 < 0) {
    iVar4 = 0;
  }
  if (*(int *)(param_3 + 0xc) < iVar4) {
    FUN_80290ee0((int)local_44,(uint)local_40 - (iVar4 - *(int *)(param_3 + 0xc)));
    iVar4 = ((uint)local_40 - (int)local_42) + -1;
    if (iVar4 < 0) {
      iVar4 = 0;
    }
  }
  iVar6 = local_42 + 1;
  if (iVar6 < 0) {
    iVar6 = 0;
  }
  if (0x1fd < iVar6 + iVar4) {
    return (byte *)0x0;
  }
  pbVar5 = local_3f + local_40;
  for (iVar2 = 0; iVar2 < *(int *)(param_3 + 0xc) - iVar4; iVar2 = iVar2 + 1) {
    pbVar8 = pbVar8 + -1;
    *pbVar8 = 0x30;
  }
  for (iVar2 = 0; (iVar2 < iVar4 && (iVar2 < (int)(uint)local_40)); iVar2 = iVar2 + 1) {
    pbVar5 = pbVar5 + -1;
    pbVar8 = pbVar8 + -1;
    *pbVar8 = *pbVar5;
  }
  uVar3 = iVar4 - iVar2;
  if (iVar2 < iVar4) {
    uVar9 = uVar3 >> 3;
    if (uVar9 != 0) {
      do {
        pbVar8[-1] = 0x30;
        pbVar8[-2] = 0x30;
        pbVar8[-3] = 0x30;
        pbVar8[-4] = 0x30;
        pbVar8[-5] = 0x30;
        pbVar8[-6] = 0x30;
        pbVar8[-7] = 0x30;
        pbVar8 = pbVar8 + -8;
        *pbVar8 = 0x30;
        uVar9 = uVar9 - 1;
      } while (uVar9 != 0);
      uVar3 = uVar3 & 7;
      if (uVar3 == 0) goto LAB_80290dac;
    }
    do {
      pbVar8 = pbVar8 + -1;
      *pbVar8 = 0x30;
      uVar3 = uVar3 - 1;
    } while (uVar3 != 0);
  }
LAB_80290dac:
  if ((*(int *)(param_3 + 0xc) != 0) || (*(char *)(param_3 + 3) != '\0')) {
    pbVar8 = pbVar8 + -1;
    *pbVar8 = 0x2e;
  }
  if (iVar6 == 0) {
    pbVar8 = pbVar8 + -1;
    *pbVar8 = 0x30;
  }
  else {
    for (iVar4 = 0; iVar4 < (int)(iVar6 - (uint)local_40); iVar4 = iVar4 + 1) {
      pbVar8 = pbVar8 + -1;
      *pbVar8 = 0x30;
    }
    uVar3 = iVar6 - iVar4;
    if (iVar4 < iVar6) {
      uVar9 = uVar3 >> 3;
      if (uVar9 != 0) {
        do {
          pbVar8[-1] = pbVar5[-1];
          pbVar8[-2] = pbVar5[-2];
          pbVar8[-3] = pbVar5[-3];
          pbVar8[-4] = pbVar5[-4];
          pbVar8[-5] = pbVar5[-5];
          pbVar8[-6] = pbVar5[-6];
          pbVar8[-7] = pbVar5[-7];
          pbVar5 = pbVar5 + -8;
          pbVar8 = pbVar8 + -8;
          *pbVar8 = *pbVar5;
          uVar9 = uVar9 - 1;
        } while (uVar9 != 0);
        uVar3 = uVar3 & 7;
        if (uVar3 == 0) goto LAB_80290e78;
      }
      do {
        pbVar5 = pbVar5 + -1;
        pbVar8 = pbVar8 + -1;
        *pbVar8 = *pbVar5;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
  }
LAB_80290e78:
  if (local_44[0] == '\0') {
    if (*(char *)(param_3 + 1) == '\x01') {
      pbVar8 = pbVar8 + -1;
      *pbVar8 = 0x2b;
    }
    else if (*(char *)(param_3 + 1) == '\x02') {
      pbVar8 = pbVar8 + -1;
      *pbVar8 = 0x20;
    }
  }
  else {
    pbVar8 = pbVar8 + -1;
    *pbVar8 = 0x2d;
  }
  return pbVar8;
}

