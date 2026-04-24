// Function: FUN_8003e1e8
// Entry: 8003e1e8
// Size: 684 bytes

void FUN_8003e1e8(undefined4 param_1,undefined4 param_2,int *param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,uint param_7,uint param_8)

{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  undefined *puVar12;
  int iVar13;
  undefined1 *puVar14;
  undefined1 *puVar15;
  undefined8 uVar16;
  undefined auStack104 [12];
  float local_5c;
  float local_4c;
  float local_3c;
  
  uVar16 = FUN_802860bc();
  iVar7 = (int)((ulonglong)uVar16 >> 0x20);
  puVar15 = &DAT_802caed0;
  iVar6 = FUN_80022a48();
  if (DAT_803dcc48 == 1) {
    if ((param_8 & 0xff) == 0) {
      FUN_8003be38(iVar7,(int)uVar16,param_5,param_4);
    }
    else {
      iVar8 = FUN_80022a48();
      bVar1 = *(byte *)(iVar7 + 0xf3);
      bVar2 = *(byte *)(iVar7 + 0xf4);
      iVar7 = iVar8 + 0x2700;
      FUN_800229c4(0);
      for (iVar13 = 0; iVar13 < (int)((uint)bVar1 + (uint)bVar2); iVar13 = iVar13 + 1) {
        FUN_80246eb4(param_5,iVar7,iVar8);
        iVar7 = iVar7 + 0x40;
        iVar8 = iVar8 + 0x30;
      }
      DAT_803dcc48 = 2;
    }
  }
  uVar11 = param_3[4];
  uVar5 = *(undefined *)(*param_3 + ((int)uVar11 >> 3));
  iVar7 = *param_3 + ((int)uVar11 >> 3);
  uVar3 = *(undefined *)(iVar7 + 1);
  uVar4 = *(undefined *)(iVar7 + 2);
  param_3[4] = uVar11 + 4;
  uVar11 = (uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar5)) >> (uVar11 & 7)) & 0xf;
  if (0x14 < uVar11) {
    FUN_8007d6dc(s__renderOpMatrix__ERROR_CASE_numM_802caf18,uVar11);
  }
  puVar14 = &DAT_802caedc;
  for (iVar7 = 0; iVar7 < (int)uVar11; iVar7 = iVar7 + 1) {
    uVar10 = param_3[4];
    puVar12 = (undefined *)(*param_3 + ((int)uVar10 >> 3));
    uVar3 = *puVar12;
    uVar4 = puVar12[1];
    uVar5 = puVar12[2];
    param_3[4] = uVar10 + 8;
    if (DAT_803dcc48 == 2) {
      iVar8 = iVar6 + ((uint3)(CONCAT12(uVar5,CONCAT11(uVar4,uVar3)) >> (uVar10 & 7)) & 0xff) * 0x30
      ;
      iVar13 = iVar8 + 0x12c0;
      FUN_8025d0a8(iVar8,*puVar15);
      if (((param_8 & 0xff) == 0) && ((param_7 & 0xff) != 0)) {
        FUN_8025d160(iVar13,*puVar14,0);
      }
      if (((param_8 & 0xff) == 0) && ((param_6 & 0xff) != 0)) {
        FUN_8025d0e4(iVar13,*puVar15);
      }
    }
    else {
      uVar9 = FUN_8002856c((int)uVar16);
      FUN_80246eb4(param_5,uVar9,auStack104);
      FUN_8025d0a8(auStack104,*puVar15);
      if (((param_8 & 0xff) == 0) && (((param_6 & 0xff) != 0 || ((param_7 & 0xff) != 0)))) {
        local_5c = FLOAT_803dea04;
        local_4c = FLOAT_803dea04;
        local_3c = FLOAT_803dea04;
        FUN_80246eb4(auStack104,param_4,auStack104);
        if ((param_7 & 0xff) != 0) {
          FUN_8025d160(auStack104,*puVar14,0);
        }
        if ((param_6 & 0xff) != 0) {
          FUN_8025d0e4(auStack104,*puVar15);
        }
      }
    }
    puVar15 = puVar15 + 1;
    puVar14 = puVar14 + 1;
  }
  FUN_80286108();
  return;
}

