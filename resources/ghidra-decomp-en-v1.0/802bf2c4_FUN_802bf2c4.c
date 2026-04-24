// Function: FUN_802bf2c4
// Entry: 802bf2c4
// Size: 532 bytes

void FUN_802bf2c4(undefined4 param_1,undefined4 param_2,int *param_3)

{
  short *psVar1;
  short sVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined8 uVar7;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40 [4];
  undefined auStack48 [12];
  float local_24;
  float local_1c;
  
  uVar7 = FUN_802860dc();
  psVar1 = (short *)((ulonglong)uVar7 >> 0x20);
  iVar5 = (int)uVar7;
  FUN_8002b9ec();
  local_40[0] = DAT_802c2d3c;
  local_40[1] = DAT_802c2d40;
  local_40[2] = DAT_802c2d44;
  local_40[3] = DAT_802c2d48;
  local_48 = DAT_803e8398;
  local_44 = DAT_803e839c;
  iVar3 = *(int *)(psVar1 + 0x5c);
  if (iVar5 == 3) {
    if ((psVar1[0x58] & 0x1000U) == 0) {
      *param_3 = 1;
    }
    else {
      *param_3 = 0;
    }
  }
  else if (iVar5 < 3) {
    if (1 < iVar5) {
      if (((psVar1[0x58] & 0x1000U) == 0) && (-1 < *(char *)(iVar3 + 0xbc1))) {
        sVar2 = *psVar1;
        iVar5 = 0;
        puVar6 = &local_48;
        do {
          iVar3 = FUN_8001ffb4((int)*(short *)puVar6);
          if (iVar3 != 0) break;
          puVar6 = (undefined4 *)((int)puVar6 + 2);
          iVar5 = iVar5 + 1;
        } while (iVar5 < 4);
        if ((iVar5 != 4) && (iVar5 = FUN_80114184(local_40[iVar5],auStack48), iVar5 != 0)) {
          sVar2 = FUN_800217c0((double)(local_24 - *(float *)(psVar1 + 6)),
                               (double)(local_1c - *(float *)(psVar1 + 10)));
          sVar2 = sVar2 + DAT_803dc79c;
        }
        uVar4 = (uint)(short)(sVar2 - DAT_803de4dc);
        if (0x8000 < (int)uVar4) {
          uVar4 = (uint)(short)((sVar2 - DAT_803de4dc) + 1);
        }
        if ((short)uVar4 < -0x8000) {
          uVar4 = (uint)(short)((short)uVar4 + -1);
        }
        sVar2 = ((short)uVar4 >> 4) + (ushort)((short)uVar4 < 0 && (uVar4 & 0xf) != 0);
        if (sVar2 < -0x50) {
          sVar2 = -0x50;
        }
        else if (0x50 < sVar2) {
          sVar2 = 0x50;
        }
        DAT_803de4dc = DAT_803de4dc + sVar2;
        *param_3 = (int)DAT_803de4dc;
      }
      else {
        *param_3 = (int)*psVar1;
        DAT_803de4dc = *psVar1;
        *(byte *)(iVar3 + 0xbc1) = *(byte *)(iVar3 + 0xbc1) & 0x7f;
      }
    }
  }
  else if (iVar5 < 5) {
    *param_3 = 1;
  }
  FUN_80286128();
  return;
}

