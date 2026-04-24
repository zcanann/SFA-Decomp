// Function: FUN_8018cfa4
// Entry: 8018cfa4
// Size: 556 bytes

void FUN_8018cfa4(void)

{
  int iVar1;
  int iVar2;
  short sVar3;
  bool bVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int *piVar7;
  undefined auStack40 [4];
  float local_24;
  float local_20;
  float local_1c;
  
  iVar1 = FUN_802860dc();
  piVar7 = *(int **)(iVar1 + 0xb8);
  FUN_8002b9ec();
  iVar2 = (**(code **)(*DAT_803dca58 + 0x24))(auStack40);
  if (iVar2 == 0) {
    if (*piVar7 != 0) {
      FUN_8001db6c((double)FLOAT_803e3d78,*piVar7,0);
    }
    FUN_80035dac(iVar1);
    piVar7[1] = (int)((float)piVar7[1] - FLOAT_803db414);
    if (FLOAT_803e3d7c < (float)piVar7[1]) {
      uVar5 = 0;
    }
    else {
      uVar5 = 3;
      piVar7[1] = (int)((float)piVar7[1] + FLOAT_803e3d80);
    }
    uVar6 = 0;
    bVar4 = false;
    if (*(char *)((int)piVar7 + 0x12) != '\0') {
      FUN_8000db90(iVar1,0x9e);
      *(undefined *)((int)piVar7 + 0x12) = 0;
    }
  }
  else {
    if (*piVar7 != 0) {
      FUN_8001db6c((double)FLOAT_803e3d78,*piVar7,1);
    }
    FUN_80035df4(iVar1,0x1f,1,0);
    piVar7[2] = (int)((float)piVar7[2] - FLOAT_803db414);
    bVar4 = (float)piVar7[2] <= FLOAT_803e3d7c;
    if (bVar4) {
      piVar7[2] = (int)((float)piVar7[2] + FLOAT_803e3d78);
    }
    uVar6 = 2;
    uVar5 = 0;
    if (*(char *)((int)piVar7 + 0x12) == '\0') {
      FUN_8000dcbc(iVar1,0x9e);
      *(undefined *)((int)piVar7 + 0x12) = 1;
    }
  }
  local_24 = FLOAT_803e3d7c;
  local_20 = FLOAT_803e3d80;
  local_1c = FLOAT_803e3d7c;
  FUN_80098b18((double)(FLOAT_803e3d84 * *(float *)(iVar1 + 8)),iVar1,uVar6,uVar5,bVar4,&local_24);
  iVar1 = *piVar7;
  if (((iVar1 != 0) && (*(char *)(iVar1 + 0x2f8) != '\0')) && (*(char *)(iVar1 + 0x4c) != '\0')) {
    sVar3 = FUN_800221a0(0xffffffe7,0x19);
    iVar1 = *piVar7;
    sVar3 = (ushort)*(byte *)(iVar1 + 0x2f9) + *(char *)(iVar1 + 0x2fa) + sVar3;
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar1 + 0x2fa) = 0;
    }
    else if (0xff < sVar3) {
      sVar3 = 0xff;
      *(undefined *)(iVar1 + 0x2fa) = 0;
    }
    *(char *)(*piVar7 + 0x2f9) = (char)sVar3;
  }
  FUN_80286128();
  return;
}

