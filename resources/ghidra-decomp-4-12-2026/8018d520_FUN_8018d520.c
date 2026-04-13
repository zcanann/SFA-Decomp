// Function: FUN_8018d520
// Entry: 8018d520
// Size: 556 bytes

void FUN_8018d520(void)

{
  bool bVar1;
  float fVar2;
  short sVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  undefined4 uVar8;
  int *piVar9;
  undefined auStack_28 [4];
  float local_24;
  float local_20;
  float local_1c;
  
  uVar4 = FUN_80286840();
  piVar9 = *(int **)(uVar4 + 0xb8);
  FUN_8002bac4();
  iVar5 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_28);
  if (iVar5 == 0) {
    if (*piVar9 != 0) {
      FUN_8001dc30((double)FLOAT_803e4a10,*piVar9,'\0');
    }
    FUN_80035ea4(uVar4);
    piVar9[1] = (int)((float)piVar9[1] - FLOAT_803dc074);
    if (FLOAT_803e4a14 < (float)piVar9[1]) {
      uVar7 = 0;
    }
    else {
      uVar7 = 3;
      piVar9[1] = (int)((float)piVar9[1] + FLOAT_803e4a18);
    }
    uVar8 = 0;
    uVar6 = 0;
    if (*(char *)((int)piVar9 + 0x12) != '\0') {
      FUN_8000dbb0();
      *(undefined *)((int)piVar9 + 0x12) = 0;
    }
  }
  else {
    if (*piVar9 != 0) {
      FUN_8001dc30((double)FLOAT_803e4a10,*piVar9,'\x01');
    }
    FUN_80035eec(uVar4,0x1f,1,0);
    piVar9[2] = (int)((float)piVar9[2] - FLOAT_803dc074);
    fVar2 = (float)piVar9[2];
    bVar1 = fVar2 <= FLOAT_803e4a14;
    if (bVar1) {
      piVar9[2] = (int)(fVar2 + FLOAT_803e4a10);
    }
    uVar6 = (uint)bVar1;
    uVar8 = 2;
    uVar7 = 0;
    if (*(char *)((int)piVar9 + 0x12) == '\0') {
      FUN_8000dcdc(uVar4,0x9e);
      *(undefined *)((int)piVar9 + 0x12) = 1;
    }
  }
  local_24 = FLOAT_803e4a14;
  local_20 = FLOAT_803e4a18;
  local_1c = FLOAT_803e4a14;
  FUN_80098da4(uVar4,uVar8,uVar7,uVar6,&local_24);
  iVar5 = *piVar9;
  if (((iVar5 != 0) && (*(char *)(iVar5 + 0x2f8) != '\0')) && (*(char *)(iVar5 + 0x4c) != '\0')) {
    uVar4 = FUN_80022264(0xffffffe7,0x19);
    iVar5 = *piVar9;
    sVar3 = (ushort)*(byte *)(iVar5 + 0x2f9) + (short)*(char *)(iVar5 + 0x2fa) + (short)uVar4;
    if (sVar3 < 0) {
      sVar3 = 0;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    else if (0xff < sVar3) {
      sVar3 = 0xff;
      *(undefined *)(iVar5 + 0x2fa) = 0;
    }
    *(char *)(*piVar9 + 0x2f9) = (char)sVar3;
  }
  FUN_8028688c();
  return;
}

