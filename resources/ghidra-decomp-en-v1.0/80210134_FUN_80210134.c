// Function: FUN_80210134
// Entry: 80210134
// Size: 1060 bytes

void FUN_80210134(int param_1)

{
  byte bVar1;
  char cVar6;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined uVar7;
  short sVar5;
  int iVar8;
  int iVar9;
  int *piVar10;
  int local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined2 local_4c;
  float local_48;
  float local_44;
  float local_40;
  uint local_3c [4];
  uint local_2c [7];
  
  piVar10 = *(int **)(param_1 + 0xb8);
  if ((*(char *)((int)piVar10 + 0xa1) != '\0') && ((*(byte *)((int)piVar10 + 0xaa) >> 6 & 1) != 0))
  {
    piVar10[0x2b] = (int)FLOAT_803e66f0;
  }
  *(undefined *)((int)piVar10 + 0xa1) = 0;
  *(undefined *)(piVar10 + 0x28) = 0xff;
  cVar6 = *(char *)(piVar10 + 0x29);
  if (cVar6 < '\0') {
    if (cVar6 < -10) {
      *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
      *(ushort *)(*piVar10 + 6) = *(ushort *)(*piVar10 + 6) | 0x4000;
      FUN_80035f00(param_1);
      FUN_80035f00(*piVar10);
    }
    else {
      *(char *)(piVar10 + 0x29) = cVar6 + -1;
    }
  }
  else {
    FUN_80035f20(param_1);
    if (*piVar10 != 0) {
      FUN_80035f20();
    }
    local_54 = DAT_802c2540;
    local_50 = DAT_802c2544;
    local_4c = DAT_802c2548;
    if (*(char *)((int)piVar10 + 0xa2) != *(char *)((int)piVar10 + 0xa3)) {
      if (*(int *)(param_1 + 200) != 0) {
        FUN_8002cbc4();
        *(undefined4 *)(param_1 + 200) = 0;
        *(undefined *)(param_1 + 0xeb) = 0;
      }
      if (('\0' < *(char *)((int)piVar10 + 0xa2)) && (cVar6 = FUN_8002e04c(), cVar6 != '\0')) {
        uVar2 = FUN_8002bdf4(0x18,(int)*(short *)((int)&local_54 +
                                                 *(char *)((int)piVar10 + 0xa2) * 2));
        uVar2 = FUN_8002df90(uVar2,4,(int)*(char *)(param_1 + 0xac),0xffffffff,
                             *(undefined4 *)(param_1 + 0x30));
        *(undefined4 *)(param_1 + 200) = uVar2;
        *(undefined *)(param_1 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar10 + 0xa3) = *(undefined *)((int)piVar10 + 0xa2);
    }
    if (*piVar10 == 0) {
      iVar3 = FUN_80036f50(10,&local_58);
      iVar4 = FUN_8007fff8(&DAT_8032a310,6,(int)*(short *)(param_1 + 0x46));
      for (iVar9 = 0; iVar9 < local_58; iVar9 = iVar9 + 1) {
        iVar8 = *(int *)(iVar3 + iVar9 * 4);
        if (iVar4 == *(short *)(iVar8 + 0x46)) {
          *piVar10 = iVar8;
          iVar9 = local_58;
        }
      }
    }
    iVar9 = FUN_8001ffb4((int)*(short *)piVar10[1]);
    if (iVar9 != 0) {
      if ((((*piVar10 != 0) && (*(char *)(piVar10 + 0x29) != '\0')) &&
          ((int)*(short *)(param_1 + 0xa0) == (uint)*(ushort *)(piVar10 + 0x2a))) &&
         ((iVar9 = FUN_801ec9f4(), iVar9 != 0 && (iVar9 = FUN_800801a8(piVar10 + 0x26), iVar9 != 0))
         )) {
        uVar7 = FUN_800221a0(0,1);
        piVar10[0x25] = *(ushort *)(piVar10 + 0x2a) + 5;
        uVar2 = FUN_8002b9ec();
        sVar5 = FUN_800385e8(param_1,uVar2,0);
        if ((sVar5 < 0) && (*(short *)(param_1 + 0x46) != 0x389)) {
          FUN_80030334((double)FLOAT_803e66f0,param_1,*(ushort *)(piVar10 + 0x2a) + 5,0);
          FUN_8020f214(*piVar10,param_1,uVar7,0);
        }
        else {
          FUN_80030334((double)FLOAT_803e66f0,param_1,*(ushort *)(piVar10 + 0x2a) + 6,0);
          FUN_8020f214(*piVar10,param_1,uVar7,2);
        }
        iVar9 = FUN_801ec9bc(*piVar10);
        FUN_80080178(piVar10 + 0x26,(int)(short)*(undefined4 *)(&DAT_8032a33c + iVar9 * 4));
      }
      if (*piVar10 != 0) {
        FUN_8020f384(param_1);
      }
      iVar9 = FUN_80080100(300);
      if (iVar9 != 0) {
        FUN_8000bb18(param_1,0x2e5);
      }
      if (*(char *)(piVar10 + 0x29) < 4) {
        local_2c[0] = DAT_802c2520;
        local_2c[1] = DAT_802c2524;
        local_2c[2] = DAT_802c2528;
        local_2c[3] = DAT_802c252c;
        local_3c[0] = DAT_802c2530;
        local_3c[1] = DAT_802c2534;
        local_3c[2] = DAT_802c2538;
        local_3c[3] = DAT_802c253c;
        iVar9 = 3 - *(char *)(piVar10 + 0x29);
        bVar1 = *(byte *)((int)piVar10 + 0xa6);
        *(byte *)((int)piVar10 + 0xa6) = bVar1 + 1;
        if ((uint)bVar1 != ((int)(uint)bVar1 / DAT_803dc220) * DAT_803dc220) {
          local_48 = FLOAT_803e66f0;
          local_44 = FLOAT_803dc21c;
          local_40 = FLOAT_803e66f0;
          FUN_80098b18((double)FLOAT_803dc218,param_1,local_2c[iVar9] & 0xff,local_3c[iVar9] & 0xff,
                       0,&local_48);
        }
      }
    }
  }
  return;
}

