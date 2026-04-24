// Function: FUN_802bfa34
// Entry: 802bfa34
// Size: 532 bytes

void FUN_802bfa34(undefined4 param_1,undefined4 param_2,int *param_3)

{
  short sVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  undefined8 uVar7;
  undefined4 local_48;
  undefined4 local_44;
  int local_40 [4];
  undefined2 auStack_30 [24];
  
  uVar7 = FUN_80286840();
  psVar6 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  FUN_8002bac4();
  local_40[0] = DAT_802c34bc;
  local_40[1] = DAT_802c34c0;
  local_40[2] = DAT_802c34c4;
  local_40[3] = DAT_802c34c8;
  local_48 = DAT_803e9030;
  local_44 = DAT_803e9034;
  iVar4 = *(int *)(psVar6 + 0x5c);
  if (iVar5 == 3) {
    if ((psVar6[0x58] & 0x1000U) == 0) {
      *param_3 = 1;
    }
    else {
      *param_3 = 0;
    }
  }
  else if (iVar5 < 3) {
    if (1 < iVar5) {
      if (((psVar6[0x58] & 0x1000U) == 0) && (-1 < *(char *)(iVar4 + 0xbc1))) {
        sVar1 = *psVar6;
        iVar5 = 0;
        psVar6 = (short *)&local_48;
        do {
          uVar3 = FUN_80020078((int)*psVar6);
          if (uVar3 != 0) break;
          psVar6 = psVar6 + 1;
          iVar5 = iVar5 + 1;
        } while (iVar5 < 4);
        if ((iVar5 != 4) && (iVar5 = FUN_80114420(local_40[iVar5],auStack_30), iVar5 != 0)) {
          iVar5 = FUN_80021884();
          sVar1 = (short)iVar5 + DAT_803dd404;
        }
        uVar2 = sVar1 - DAT_803df15c;
        if (0x8000 < (short)uVar2) {
          uVar2 = uVar2 + 1;
        }
        if ((short)uVar2 < -0x8000) {
          uVar2 = uVar2 - 1;
        }
        sVar1 = ((short)uVar2 >> 4) + (ushort)((short)uVar2 < 0 && (uVar2 & 0xf) != 0);
        if (sVar1 < -0x50) {
          sVar1 = -0x50;
        }
        else if (0x50 < sVar1) {
          sVar1 = 0x50;
        }
        DAT_803df15c = DAT_803df15c + sVar1;
        *param_3 = (int)DAT_803df15c;
      }
      else {
        *param_3 = (int)*psVar6;
        DAT_803df15c = *psVar6;
        *(byte *)(iVar4 + 0xbc1) = *(byte *)(iVar4 + 0xbc1) & 0x7f;
      }
    }
  }
  else if (iVar5 < 5) {
    *param_3 = 1;
  }
  FUN_8028688c();
  return;
}

