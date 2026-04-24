// Function: FUN_8003e5fc
// Entry: 8003e5fc
// Size: 912 bytes

void FUN_8003e5fc(undefined4 param_1,undefined4 param_2,int *param_3,int *param_4,uint param_5,
                 undefined *param_6,undefined *param_7)

{
  undefined uVar1;
  undefined uVar2;
  undefined uVar3;
  bool bVar4;
  uint3 uVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  undefined8 uVar14;
  int local_38;
  undefined auStack52 [52];
  
  uVar14 = FUN_802860c8();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  iVar7 = (int)uVar14;
  FUN_802573f8();
  if (*(byte *)(iVar6 + 0xf3) < 2) {
    FUN_8025d124(0);
    *param_7 = 1;
  }
  else {
    FUN_80256978(0,1);
    iVar12 = 1;
    if ((*param_3 != 0) || (param_3[1] != 0)) {
      iVar13 = iVar12;
      if (*(int *)(iVar7 + 0x34) != 0) {
        FUN_80256978(1,1);
        iVar13 = 3;
        FUN_80256978(2,1);
      }
      iVar12 = iVar13 + 1;
      FUN_80256978(iVar13,1);
    }
    iVar13 = 8;
    for (iVar10 = 0; iVar10 < (int)(uint)*(byte *)(iVar6 + 0xfa); iVar10 = iVar10 + 1) {
      if (((param_5 & 0xff) == 4) && (iVar10 == 0)) {
        if ((DAT_803dcc5c == 0) || (FUN_8001d7f8(DAT_803dcc64,&local_38,auStack52), local_38 != 0))
        {
          bVar4 = false;
        }
        else {
          bVar4 = true;
        }
      }
      else if ((iVar10 < DAT_803dcc5c) && ((param_5 & 0xff) == 0)) {
        bVar4 = true;
      }
      else {
        bVar4 = false;
      }
      if (bVar4) {
        FUN_80256978(iVar12,1);
        iVar11 = iVar13;
        iVar12 = iVar12 + 1;
      }
      else {
        iVar11 = iVar13 + -1;
        FUN_80256978(iVar13,1);
      }
      iVar13 = iVar11;
    }
    if (iVar12 < 2) {
      *param_7 = 0;
    }
    else {
      *param_7 = 1;
    }
  }
  uVar9 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
  iVar12 = *param_4 + ((int)uVar9 >> 3);
  uVar1 = *(undefined *)(iVar12 + 1);
  uVar2 = *(undefined *)(iVar12 + 2);
  param_4[4] = uVar9 + 1;
  if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
    uVar8 = 2;
  }
  else {
    uVar8 = 3;
  }
  FUN_80256978(9,uVar8);
  if ((*(byte *)(iVar7 + 0x40) & 1) == 0) {
    *param_6 = 0;
  }
  else {
    uVar9 = param_4[4];
    uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
    iVar12 = *param_4 + ((int)uVar9 >> 3);
    uVar1 = *(undefined *)(iVar12 + 1);
    uVar2 = *(undefined *)(iVar12 + 2);
    param_4[4] = uVar9 + 1;
    uVar5 = CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7);
    if ((*(byte *)(iVar6 + 0x24) & 8) == 0) {
      if ((uVar5 & 1) == 0) {
        uVar8 = 2;
      }
      else {
        uVar8 = 3;
      }
      FUN_80256978(10,uVar8);
    }
    else {
      if ((uVar5 & 1) == 0) {
        uVar8 = 2;
      }
      else {
        uVar8 = 3;
      }
      FUN_80256978(0x19,uVar8);
    }
    *param_6 = 1;
  }
  if ((*(byte *)(iVar7 + 0x40) & 2) != 0) {
    uVar9 = param_4[4];
    uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
    iVar6 = *param_4 + ((int)uVar9 >> 3);
    uVar1 = *(undefined *)(iVar6 + 1);
    uVar2 = *(undefined *)(iVar6 + 2);
    param_4[4] = uVar9 + 1;
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
      uVar8 = 2;
    }
    else {
      uVar8 = 3;
    }
    FUN_80256978(0xb,uVar8);
  }
  uVar9 = param_4[4];
  uVar3 = *(undefined *)(*param_4 + ((int)uVar9 >> 3));
  iVar6 = *param_4 + ((int)uVar9 >> 3);
  uVar1 = *(undefined *)(iVar6 + 1);
  uVar2 = *(undefined *)(iVar6 + 2);
  param_4[4] = uVar9 + 1;
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(iVar7 + 0x41); iVar6 = iVar6 + 1) {
    if ((CONCAT12(uVar2,CONCAT11(uVar1,uVar3)) >> (uVar9 & 7) & 1) == 0) {
      uVar8 = 2;
    }
    else {
      uVar8 = 3;
    }
    FUN_80256978(iVar6 + 0xd,uVar8);
  }
  FUN_80286114();
  return;
}

