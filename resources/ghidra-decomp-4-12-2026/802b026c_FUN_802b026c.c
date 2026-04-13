// Function: FUN_802b026c
// Entry: 802b026c
// Size: 2908 bytes

void FUN_802b026c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)

{
  short sVar1;
  bool bVar2;
  uint uVar3;
  int iVar4;
  ushort uVar7;
  byte bVar8;
  int iVar5;
  int iVar6;
  bool bVar9;
  char *pcVar10;
  uint uVar11;
  int iVar12;
  int iVar13;
  double dVar14;
  undefined8 uVar15;
  uint local_78;
  uint local_74;
  int local_70;
  undefined4 local_6c;
  int local_68;
  int local_64;
  undefined4 local_60;
  undefined auStack_5c [12];
  float local_50;
  undefined4 uStack_4c;
  float local_48;
  undefined2 local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  
  uVar15 = FUN_80286834();
  uVar3 = (uint)((ulonglong)uVar15 >> 0x20);
  iVar6 = (int)uVar15;
  local_6c = DAT_802c33e8;
  local_68 = DAT_802c33ec;
  local_64 = DAT_802c33f0;
  local_60 = DAT_802c33f4;
  uVar11 = 0;
  dVar14 = (double)*(float *)(*(int *)(uVar3 + 0xb8) + 0x838);
  if ((double)FLOAT_803e8b70 < dVar14) {
    *(float *)(iVar6 + 0x79c) = FLOAT_803e8b3c;
  }
  if ((0 < DAT_803df0f0) && (DAT_803df0f0 = DAT_803df0f0 - (uint)DAT_803dc070, DAT_803df0f0 < 0)) {
    DAT_803df0f0 = 0;
  }
  iVar4 = FUN_80036868(uVar3,&local_78,&local_70,&local_74,&local_50,&uStack_4c,&local_48);
  if (**(char **)(iVar6 + 0x35c) < '\x01') {
    **(char **)(iVar6 + 0x35c) = '\x01';
  }
  uVar7 = FUN_80036074(uVar3);
  if ((((uVar7 == 0) || (bVar8 = FUN_8002acfc(uVar3), bVar8 != 0)) ||
      ((*(byte *)(iVar6 + 0x3f3) >> 5 & 1) != 0)) || ((*(ushort *)(uVar3 + 0xb0) & 0x1000) != 0))
  goto LAB_802b0db4;
  iVar13 = iVar4;
  if ((*(int *)(iVar6 + 0x7f0) != 0) && (iVar4 != 0)) {
    iVar13 = 0x15;
  }
  bVar9 = true;
  if (iVar13 == 0) {
    DAT_803df0f4 = 0;
    goto LAB_802b0db4;
  }
  if (local_70 != -1) {
    local_50 = local_50 + FLOAT_803dda58;
    dVar14 = (double)local_48;
    local_48 = (float)(dVar14 + (double)FLOAT_803dda5c);
  }
  if (*(short *)(param_11 + 0x278) != 0) {
    iVar13 = 0x1b;
  }
  if ((*(char *)(param_11 + 0x34d) == '\x03') && (*(char *)(param_11 + 0x34f) <= iVar13))
  goto LAB_802b0db4;
  *(char *)(param_11 + 0x34f) = (char)iVar13;
  *(undefined2 *)(uVar3 + 0xa2) = 0xffff;
  iVar12 = -1;
  bVar8 = *(byte *)(iVar6 + 0x3f0);
  if ((((bVar8 >> 4 & 1) == 0) &&
      ((((bVar8 >> 2 & 1) == 0 && ((bVar8 >> 3 & 1) == 0)) && ((bVar8 >> 5 & 1) == 0)))) &&
     (iVar5 = (int)*(short *)(param_11 + 0x274), iVar5 != 0x36)) {
    if ((((iVar5 - 1U & 0xffff) < 2) || ((iVar5 - 0x24U & 0xffff) < 2)) ||
       (*(int *)(param_11 + 0x2d0) != 0)) {
      bVar2 = true;
    }
    else {
      bVar2 = false;
    }
  }
  else {
    bVar2 = false;
  }
  switch(iVar13) {
  default:
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) != 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 0;
      iVar12 = 0x23;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 1:
    local_74 = (uint)**(char **)(iVar6 + 0x35c);
    break;
  case 2:
  case 5:
  case 0x12:
  case 0x17:
  case 0x18:
    break;
  case 4:
    if (bVar2) {
      iVar12 = 0x1f;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 7:
  case 8:
  case 9:
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) != 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 3;
      iVar12 = 0x23;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 10:
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) != 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 3;
      iVar12 = 0x23;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 0xb:
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) != 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 2;
      iVar12 = 0x23;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 0xc:
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) != 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 1;
      iVar12 = 0x23;
      *(undefined4 *)(iVar6 + 0x898) = 0;
    }
    break;
  case 0x14:
  case 0x1a:
  case 0x1f:
    dVar14 = (double)*(float *)(iVar6 + 0x79c);
    uVar11 = (uint)(dVar14 <= (double)FLOAT_803e8b3c);
    bVar9 = (*(byte *)(iVar6 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) == 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 5;
    }
    break;
  case 0x15:
    if (*(short *)(*(int *)(iVar6 + 0x7f0) + 0x46) == 0x714) {
      FUN_8000faf8();
      dVar14 = (double)FUN_8000e69c((double)FLOAT_803e8b78);
    }
    break;
  case 0x16:
    bVar9 = (*(byte *)(iVar6 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) == 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 5;
    }
    break;
  case 0x19:
    FUN_8000faf8();
    dVar14 = (double)FUN_8000e69c((double)FLOAT_803e8b78);
    break;
  case 0x1b:
    iVar12 = (int)*(short *)(param_11 + 0x278);
    break;
  case 0x1e:
    if ((*(byte *)(iVar6 + 0x3f3) >> 3 & 1) != 0) goto LAB_802b0db4;
    uVar11 = 2;
    bVar9 = (*(byte *)(iVar6 + 0x3f0) >> 1 & 1) != 0;
    if ((bVar2) && (*(int *)(param_11 + 0x2d0) == 0)) {
      *(undefined *)(iVar6 + 0x8a2) = 5;
    }
  }
  if (((*(uint *)(iVar6 + 0x360) & 0x800) == 0) && (uVar11 != 0)) {
    *(float *)(iVar6 + 0x79c) = FLOAT_803e8b74;
    *(float *)(iVar6 + 0x7a0) = FLOAT_803e8ce8;
    *(float *)(iVar6 + 0x7a4) = FLOAT_803e8b78;
    *(byte *)(iVar6 + 0x7a8) = (byte)(uVar11 << 5) | *(byte *)(iVar6 + 0x7a8) & 0x1f;
  }
  if (((*(uint *)(iVar6 + 0x360) & 0x800) != 0) && (bVar9)) {
    local_74 = 0;
    *(byte *)(iVar6 + 0x3f6) = *(byte *)(iVar6 + 0x3f6) & 0xef | 0x10;
    if ((local_78 != 0) && (*(short *)(local_78 + 0x46) != 0x2c5)) {
      if (DAT_803df0f0 == 0) {
        if (*(short *)(iVar6 + 0x81a) == 0) {
          uVar7 = 0x2ce;
        }
        else {
          uVar7 = 0x48c;
        }
        FUN_8000bb38(uVar3,uVar7);
      }
      DAT_803df0f0 = 6;
    }
    if (DAT_803df0f4 == 0) {
      iVar6 = *(int *)(*(int *)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4) + 0x50) +
              local_70 * 0x10;
      local_38 = FLOAT_803dda58 + *(float *)(iVar6 + 4);
      local_34 = *(float *)(iVar6 + 8);
      local_30 = FLOAT_803dda5c + *(float *)(iVar6 + 0xc);
      (**(code **)(*DAT_803dd708 + 8))(uVar3,0x328,&local_44,0x200001,0xffffffff,0);
      local_38 = local_38 - *(float *)(uVar3 + 0x18);
      local_34 = local_34 - *(float *)(uVar3 + 0x1c);
      local_30 = local_30 - *(float *)(uVar3 + 0x20);
      if (DAT_803df0d4 == (int *)0x0) {
        DAT_803df0d4 = (int *)FUN_80013ee8(0x5a);
      }
      uVar11 = FUN_80022264(0,0x9b);
      local_68 = local_68 + uVar11;
      uVar11 = FUN_80022264(0,0x9b);
      local_64 = local_64 + uVar11;
      local_3c = FLOAT_803e8b78;
      local_44 = 0;
      local_42 = 0;
      local_40 = 0;
      (**(code **)(*DAT_803df0d4 + 4))(uVar3,0,&local_44,1,0xffffffff,&local_6c);
      if (DAT_803df0d4 != (int *)0x0) {
        FUN_80013e4c((undefined *)DAT_803df0d4);
      }
      DAT_803df0d4 = (int *)0x0;
      DAT_803df0f4 = 10;
    }
    else {
      DAT_803df0f4 = DAT_803df0f4 + -1;
    }
    goto LAB_802b0db4;
  }
  if (local_74 == 0) {
    DAT_803df0f4 = 0;
    goto LAB_802b0db4;
  }
  iVar5 = *(int *)(uVar3 + 0xb8);
  pcVar10 = *(char **)(iVar5 + 0x35c);
  iVar13 = (int)*pcVar10 - local_74;
  if (iVar13 < 0) {
    iVar13 = 0;
  }
  else if (pcVar10[1] < iVar13) {
    iVar13 = (int)pcVar10[1];
  }
  *pcVar10 = (char)iVar13;
  if (**(char **)(iVar5 + 0x35c) < '\x01') {
    FUN_802ab1e0(dVar14,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar3);
  }
  DAT_803df0f4 = 0;
  if (local_78 != 0) {
    sVar1 = *(short *)(local_78 + 0x46);
    if (sVar1 < 0x5ba) {
      if (sVar1 == 0x13a) {
LAB_802b0a0c:
        FUN_8000bb38(local_78,0x36e);
      }
      else if (sVar1 < 0x13a) {
        if ((sVar1 == 0x33) || ((sVar1 < 0x33 && (sVar1 == 0x11)))) goto LAB_802b0a0c;
      }
      else if (sVar1 == 0x458) {
LAB_802b0a3c:
        FUN_8000bb38(local_78,0x36f);
      }
      else if (sVar1 < 0x458) {
        if (sVar1 == 0x2c5) {
          FUN_8000bb38(local_78,0xd0);
        }
      }
      else if (0x5b6 < sVar1) goto LAB_802b0a0c;
    }
    else if (sVar1 == 0x5fe) {
LAB_802b0a18:
      FUN_8000bb38(local_78,0x239);
    }
    else if (sVar1 < 0x5fe) {
      if (sVar1 < 0x5f9) {
        if (sVar1 == 0x5e1) goto LAB_802b0a0c;
      }
      else if (sVar1 < 0x5fb) goto LAB_802b0a18;
    }
    else {
      if (sVar1 == 0x842) goto LAB_802b0a3c;
      if ((sVar1 < 0x842) && (sVar1 == 0x709)) {
        FUN_8000bb38(local_78,0x486);
      }
    }
  }
  switch(iVar4) {
  case 0x14:
  case 0x1f:
    if (*(short *)(iVar6 + 0x81a) == 0) {
      uVar7 = 0x1f;
    }
    else {
      uVar7 = 0x24;
    }
    FUN_8000bb38(uVar3,uVar7);
    FUN_8000bb38(uVar3,0x393);
    bVar9 = FUN_8000b5f0(uVar3,0x394);
    if (!bVar9) {
      FUN_8000bb38(uVar3,0x394);
    }
    if ('\0' < **(char **)(iVar6 + 0x35c)) {
      FUN_8009a468(uVar3,auStack_5c,6,(int *)0x0);
    }
    break;
  default:
    if (*(short *)(iVar6 + 0x81a) == 0) {
      uVar7 = 0x1f;
    }
    else {
      uVar7 = 0x24;
    }
    FUN_8000bb38(uVar3,uVar7);
    if (local_78 == 0) {
      if ('\0' < **(char **)(iVar6 + 0x35c)) {
        FUN_8009a468(uVar3,auStack_5c,5,(int *)0x0);
      }
    }
    else {
      sVar1 = *(short *)(local_78 + 0x46);
      if (sVar1 == 0x7c8) {
        if ('\0' < **(char **)(iVar6 + 0x35c)) {
          FUN_8009a468(uVar3,auStack_5c,8,(int *)0x0);
        }
      }
      else if ((sVar1 < 0x7c8) && (sVar1 == 0x33)) {
        FUN_8000bb38(uVar3,0x36e);
        if ('\0' < **(char **)(iVar6 + 0x35c)) {
          FUN_8009a468(uVar3,auStack_5c,5,(int *)0x0);
        }
      }
      else if ('\0' < **(char **)(iVar6 + 0x35c)) {
        FUN_8009a468(uVar3,auStack_5c,5,(int *)0x0);
      }
    }
    break;
  case 0x16:
    if ((local_78 == 0) ||
       ((*(short *)(local_78 + 0x46) != 0x613 && (*(short *)(local_78 + 0x46) != 0x70f)))) {
      FUN_8000bb38(uVar3,0x367);
    }
    else {
      if (*(short *)(iVar6 + 0x81a) == 0) {
        uVar7 = 0x1f;
      }
      else {
        uVar7 = 0x24;
      }
      FUN_8000bb38(uVar3,uVar7);
    }
    break;
  case 0x1c:
    FUN_8000bb38(uVar3,0x318);
    if ('\0' < **(char **)(iVar6 + 0x35c)) {
      FUN_8009a468(uVar3,auStack_5c,8,(int *)0x0);
    }
  }
  if ('\0' < **(char **)(iVar6 + 0x35c)) {
    FUN_8002ad08(uVar3,0xb4,200,0,0,1);
  }
  if (*(short *)(param_11 + 0x274) == 0x1a) {
    FUN_8009ab54((double)FLOAT_803e8dcc,uVar3);
  }
  *(float *)(iVar6 + 0x814) = FLOAT_803e8b3c;
  uVar11 = FUN_80022264(800,0x44c);
  *(short *)(iVar6 + 0x812) = (short)uVar11;
  *(undefined *)(iVar6 + 0x800) = 0;
  iVar4 = *(int *)(iVar6 + 0x7f8);
  if (iVar4 != 0) {
    if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
      FUN_80182a5c(iVar4);
    }
    else {
      FUN_800ea9f8(iVar4);
    }
    *(ushort *)(*(int *)(iVar6 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar6 + 0x7f8) + 6) & 0xbfff;
    *(undefined4 *)(*(int *)(iVar6 + 0x7f8) + 0xf8) = 0;
    *(undefined4 *)(iVar6 + 0x7f8) = 0;
  }
  if (((iVar12 != -1) && (*(short *)(param_11 + 0x274) != iVar12)) &&
     ('\0' < **(char **)(iVar6 + 0x35c))) {
    (**(code **)(*DAT_803dd70c + 0x14))(uVar3,param_11,iVar12);
    *(undefined4 *)(param_11 + 0x304) = *(undefined4 *)(iVar6 + 0x898);
  }
LAB_802b0db4:
  FUN_80286880();
  return;
}

