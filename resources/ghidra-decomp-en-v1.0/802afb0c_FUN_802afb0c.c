// Function: FUN_802afb0c
// Entry: 802afb0c
// Size: 2908 bytes

void FUN_802afb0c(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  byte bVar2;
  short sVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined2 uVar10;
  bool bVar11;
  char *pcVar12;
  uint uVar13;
  int iVar14;
  undefined8 uVar15;
  int local_78;
  int local_74;
  int local_70;
  undefined4 local_6c;
  int local_68;
  int local_64;
  undefined4 local_60;
  undefined auStack92 [12];
  float local_50;
  undefined auStack76 [4];
  float local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  
  uVar15 = FUN_802860d0();
  iVar5 = (int)((ulonglong)uVar15 >> 0x20);
  iVar9 = (int)uVar15;
  local_6c = DAT_802c2c68;
  local_68 = DAT_802c2c6c;
  local_64 = DAT_802c2c70;
  local_60 = DAT_802c2c74;
  uVar13 = 0;
  if (FLOAT_803e7ed8 < *(float *)(*(int *)(iVar5 + 0xb8) + 0x838)) {
    *(float *)(iVar9 + 0x79c) = FLOAT_803e7ea4;
  }
  if ((0 < DAT_803de470) && (DAT_803de470 = DAT_803de470 - (uint)DAT_803db410, DAT_803de470 < 0)) {
    DAT_803de470 = 0;
  }
  iVar6 = FUN_80036770(iVar5,&local_78,&local_70,&local_74,&local_50,auStack76,&local_48);
  if (**(char **)(iVar9 + 0x35c) < '\x01') {
    **(char **)(iVar9 + 0x35c) = '\x01';
  }
  iVar7 = FUN_80035f7c(iVar5);
  if ((((iVar7 == 0) || (iVar7 = FUN_8002ac24(iVar5), iVar7 != 0)) ||
      ((*(byte *)(iVar9 + 0x3f3) >> 5 & 1) != 0)) || ((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0))
  goto LAB_802b0654;
  iVar7 = iVar6;
  if ((*(int *)(iVar9 + 0x7f0) != 0) && (iVar6 != 0)) {
    iVar7 = 0x15;
  }
  bVar1 = true;
  if (iVar7 == 0) {
    DAT_803de474 = 0;
    goto LAB_802b0654;
  }
  if (local_70 != -1) {
    local_50 = local_50 + FLOAT_803dcdd8;
    local_48 = local_48 + FLOAT_803dcddc;
  }
  if (*(short *)(param_3 + 0x278) != 0) {
    iVar7 = 0x1b;
  }
  if ((*(char *)(param_3 + 0x34d) == '\x03') && (*(char *)(param_3 + 0x34f) <= iVar7))
  goto LAB_802b0654;
  *(char *)(param_3 + 0x34f) = (char)iVar7;
  *(undefined2 *)(iVar5 + 0xa2) = 0xffff;
  iVar14 = -1;
  bVar2 = *(byte *)(iVar9 + 0x3f0);
  if ((((bVar2 >> 4 & 1) == 0) &&
      ((((bVar2 >> 2 & 1) == 0 && ((bVar2 >> 3 & 1) == 0)) && ((bVar2 >> 5 & 1) == 0)))) &&
     (iVar8 = (int)*(short *)(param_3 + 0x274), iVar8 != 0x36)) {
    if ((((iVar8 - 1U & 0xffff) < 2) || ((iVar8 - 0x24U & 0xffff) < 2)) ||
       (*(int *)(param_3 + 0x2d0) != 0)) {
      bVar11 = true;
    }
    else {
      bVar11 = false;
    }
  }
  else {
    bVar11 = false;
  }
  switch(iVar7) {
  default:
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) != 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 0;
      iVar14 = 0x23;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 1:
    local_74 = (int)**(char **)(iVar9 + 0x35c);
    break;
  case 2:
  case 5:
  case 0x12:
  case 0x17:
  case 0x18:
    break;
  case 4:
    if (bVar11) {
      iVar14 = 0x1f;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 7:
  case 8:
  case 9:
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) != 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 3;
      iVar14 = 0x23;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 10:
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) != 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 3;
      iVar14 = 0x23;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 0xb:
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) != 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 2;
      iVar14 = 0x23;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 0xc:
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) != 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 1;
      iVar14 = 0x23;
      *(undefined4 *)(iVar9 + 0x898) = 0;
    }
    break;
  case 0x14:
  case 0x1a:
  case 0x1f:
    uVar13 = (uint)(*(float *)(iVar9 + 0x79c) <= FLOAT_803e7ea4);
    bVar1 = (*(byte *)(iVar9 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) == 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 5;
    }
    break;
  case 0x15:
    if (*(short *)(*(int *)(iVar9 + 0x7f0) + 0x46) == 0x714) {
      FUN_8000fad8();
      FUN_8000e67c((double)FLOAT_803e7ee0);
    }
    break;
  case 0x16:
    bVar1 = (*(byte *)(iVar9 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) == 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 5;
    }
    break;
  case 0x19:
    FUN_8000fad8();
    FUN_8000e67c((double)FLOAT_803e7ee0);
    break;
  case 0x1b:
    iVar14 = (int)*(short *)(param_3 + 0x278);
    break;
  case 0x1e:
    if ((*(byte *)(iVar9 + 0x3f3) >> 3 & 1) != 0) goto LAB_802b0654;
    uVar13 = 2;
    bVar1 = (*(byte *)(iVar9 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar11) && (*(int *)(param_3 + 0x2d0) == 0)) {
      *(undefined *)(iVar9 + 0x8a2) = 5;
    }
  }
  if (((*(uint *)(iVar9 + 0x360) & 0x800) == 0) && (uVar13 != 0)) {
    *(float *)(iVar9 + 0x79c) = FLOAT_803e7edc;
    *(float *)(iVar9 + 0x7a0) = FLOAT_803e8050;
    *(float *)(iVar9 + 0x7a4) = FLOAT_803e7ee0;
    *(byte *)(iVar9 + 0x7a8) = (byte)(uVar13 << 5) | *(byte *)(iVar9 + 0x7a8) & 0x1f;
  }
  if (((*(uint *)(iVar9 + 0x360) & 0x800) != 0) && (bVar1)) {
    local_74 = 0;
    *(byte *)(iVar9 + 0x3f6) = *(byte *)(iVar9 + 0x3f6) & 0xef | 0x10;
    if ((local_78 != 0) && (*(short *)(local_78 + 0x46) != 0x2c5)) {
      if (DAT_803de470 == 0) {
        if (*(short *)(iVar9 + 0x81a) == 0) {
          uVar4 = 0x2ce;
        }
        else {
          uVar4 = 0x48c;
        }
        FUN_8000bb18(iVar5,uVar4);
      }
      DAT_803de470 = 6;
    }
    if (DAT_803de474 == 0) {
      iVar9 = *(int *)(*(int *)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4) + 0x50) +
              local_70 * 0x10;
      local_38 = FLOAT_803dcdd8 + *(float *)(iVar9 + 4);
      local_34 = *(float *)(iVar9 + 8);
      local_30 = FLOAT_803dcddc + *(float *)(iVar9 + 0xc);
      (**(code **)(*DAT_803dca88 + 8))(iVar5,0x328,&local_44,0x200001,0xffffffff,0);
      local_38 = local_38 - *(float *)(iVar5 + 0x18);
      local_34 = local_34 - *(float *)(iVar5 + 0x1c);
      local_30 = local_30 - *(float *)(iVar5 + 0x20);
      if (DAT_803de454 == (int *)0x0) {
        DAT_803de454 = (int *)FUN_80013ec8(0x5a,1);
      }
      iVar9 = FUN_800221a0(0,0x9b);
      local_68 = local_68 + iVar9;
      iVar9 = FUN_800221a0(0,0x9b);
      local_64 = local_64 + iVar9;
      local_3c = FLOAT_803e7ee0;
      local_44 = 0;
      local_42 = 0;
      local_40 = 0;
      (**(code **)(*DAT_803de454 + 4))(iVar5,0,&local_44,1,0xffffffff,&local_6c);
      if (DAT_803de454 != (int *)0x0) {
        FUN_80013e2c();
      }
      DAT_803de454 = (int *)0x0;
      DAT_803de474 = 10;
    }
    else {
      DAT_803de474 = DAT_803de474 + -1;
    }
    goto LAB_802b0654;
  }
  if (local_74 == 0) {
    DAT_803de474 = 0;
    goto LAB_802b0654;
  }
  iVar8 = *(int *)(iVar5 + 0xb8);
  pcVar12 = *(char **)(iVar8 + 0x35c);
  iVar7 = *pcVar12 - local_74;
  if (iVar7 < 0) {
    iVar7 = 0;
  }
  else if (pcVar12[1] < iVar7) {
    iVar7 = (int)pcVar12[1];
  }
  *pcVar12 = (char)iVar7;
  if (**(char **)(iVar8 + 0x35c) < '\x01') {
    FUN_802aaa80(iVar5);
  }
  DAT_803de474 = 0;
  if (local_78 != 0) {
    sVar3 = *(short *)(local_78 + 0x46);
    if (sVar3 < 0x5ba) {
      if (sVar3 == 0x13a) {
LAB_802b02ac:
        FUN_8000bb18(local_78,0x36e);
      }
      else if (sVar3 < 0x13a) {
        if ((sVar3 == 0x33) || ((sVar3 < 0x33 && (sVar3 == 0x11)))) goto LAB_802b02ac;
      }
      else if (sVar3 == 0x458) {
LAB_802b02dc:
        FUN_8000bb18(local_78,0x36f);
      }
      else if (sVar3 < 0x458) {
        if (sVar3 == 0x2c5) {
          FUN_8000bb18(local_78,0xd0);
        }
      }
      else if (0x5b6 < sVar3) goto LAB_802b02ac;
    }
    else if (sVar3 == 0x5fe) {
LAB_802b02b8:
      FUN_8000bb18(local_78,0x239);
    }
    else if (sVar3 < 0x5fe) {
      if (sVar3 < 0x5f9) {
        if (sVar3 == 0x5e1) goto LAB_802b02ac;
      }
      else if (sVar3 < 0x5fb) goto LAB_802b02b8;
    }
    else {
      if (sVar3 == 0x842) goto LAB_802b02dc;
      if ((sVar3 < 0x842) && (sVar3 == 0x709)) {
        FUN_8000bb18(local_78,0x486);
      }
    }
  }
  switch(iVar6) {
  case 0x14:
  case 0x1f:
    if (*(short *)(iVar9 + 0x81a) == 0) {
      uVar4 = 0x1f;
    }
    else {
      uVar4 = 0x24;
    }
    FUN_8000bb18(iVar5,uVar4);
    FUN_8000bb18(iVar5,0x393);
    iVar6 = FUN_8000b5d0(iVar5,0x394);
    if (iVar6 == 0) {
      FUN_8000bb18(iVar5,0x394);
    }
    if ('\0' < **(char **)(iVar9 + 0x35c)) {
      FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,6,0);
    }
    break;
  default:
    if (*(short *)(iVar9 + 0x81a) == 0) {
      uVar4 = 0x1f;
    }
    else {
      uVar4 = 0x24;
    }
    FUN_8000bb18(iVar5,uVar4);
    if (local_78 == 0) {
      if ('\0' < **(char **)(iVar9 + 0x35c)) {
        FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,5,0);
      }
    }
    else {
      sVar3 = *(short *)(local_78 + 0x46);
      if (sVar3 == 0x7c8) {
        if ('\0' < **(char **)(iVar9 + 0x35c)) {
          FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,8,0);
        }
      }
      else if ((sVar3 < 0x7c8) && (sVar3 == 0x33)) {
        FUN_8000bb18(iVar5,0x36e);
        if ('\0' < **(char **)(iVar9 + 0x35c)) {
          FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,5,0);
        }
      }
      else if ('\0' < **(char **)(iVar9 + 0x35c)) {
        FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,5,0);
      }
    }
    break;
  case 0x16:
    if ((local_78 == 0) ||
       ((*(short *)(local_78 + 0x46) != 0x613 && (*(short *)(local_78 + 0x46) != 0x70f)))) {
      FUN_8000bb18(iVar5,0x367);
    }
    else {
      if (*(short *)(iVar9 + 0x81a) == 0) {
        uVar4 = 0x1f;
      }
      else {
        uVar4 = 0x24;
      }
      FUN_8000bb18(iVar5,uVar4);
    }
    break;
  case 0x1c:
    FUN_8000bb18(iVar5,0x318);
    if ('\0' < **(char **)(iVar9 + 0x35c)) {
      FUN_8009a1dc((double)FLOAT_803e8024,iVar5,auStack92,8,0);
    }
  }
  if ('\0' < **(char **)(iVar9 + 0x35c)) {
    FUN_8002ac30(iVar5,0xb4,200,0,0,1);
  }
  if (*(short *)(param_3 + 0x274) == 0x1a) {
    FUN_8009a8c8((double)FLOAT_803e8134,iVar5);
  }
  *(float *)(iVar9 + 0x814) = FLOAT_803e7ea4;
  uVar10 = FUN_800221a0(800,0x44c);
  *(undefined2 *)(iVar9 + 0x812) = uVar10;
  *(undefined *)(iVar9 + 0x800) = 0;
  if (*(int *)(iVar9 + 0x7f8) != 0) {
    sVar3 = *(short *)(*(int *)(iVar9 + 0x7f8) + 0x46);
    if ((sVar3 == 0x3cf) || (sVar3 == 0x662)) {
      FUN_80182504();
    }
    else {
      FUN_800ea774();
    }
    *(ushort *)(*(int *)(iVar9 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar9 + 0x7f8) + 6) & 0xbfff;
    *(undefined4 *)(*(int *)(iVar9 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(iVar9 + 0x7f8) = 0;
  }
  if (((iVar14 != -1) && (*(short *)(param_3 + 0x274) != iVar14)) &&
     ('\0' < **(char **)(iVar9 + 0x35c))) {
    (**(code **)(*DAT_803dca8c + 0x14))(iVar5,param_3,iVar14);
    *(undefined4 *)(param_3 + 0x304) = *(undefined4 *)(iVar9 + 0x898);
  }
LAB_802b0654:
  FUN_8028611c();
  return;
}

