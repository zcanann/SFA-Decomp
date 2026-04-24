// Function: FUN_8003e060
// Entry: 8003e060
// Size: 392 bytes

void FUN_8003e060(undefined4 param_1,undefined4 param_2,int *param_3,undefined4 param_4)

{
  byte bVar1;
  byte bVar2;
  undefined uVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined uVar7;
  undefined uVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  uint uVar12;
  uint uVar13;
  undefined *puVar14;
  int iVar15;
  int iVar16;
  undefined1 *puVar17;
  undefined8 uVar18;
  undefined auStack88 [88];
  
  uVar18 = FUN_802860d0();
  iVar15 = (int)((ulonglong)uVar18 >> 0x20);
  iVar9 = FUN_80022a48();
  if (DAT_803dcc48 == 1) {
    iVar10 = FUN_80022a48();
    bVar1 = *(byte *)(iVar15 + 0xf3);
    bVar2 = *(byte *)(iVar15 + 0xf4);
    iVar15 = iVar10 + 0x2700;
    FUN_800229c4(0);
    for (iVar16 = 0; iVar16 < (int)((uint)bVar1 + (uint)bVar2); iVar16 = iVar16 + 1) {
      FUN_80246eb4(param_4,iVar15,iVar10);
      iVar15 = iVar15 + 0x40;
      iVar10 = iVar10 + 0x30;
    }
    DAT_803dcc48 = 2;
  }
  uVar13 = param_3[4];
  uVar8 = *(undefined *)(*param_3 + ((int)uVar13 >> 3));
  iVar15 = *param_3 + ((int)uVar13 >> 3);
  uVar3 = *(undefined *)(iVar15 + 1);
  uVar4 = *(undefined *)(iVar15 + 2);
  param_3[4] = uVar13 + 4;
  puVar17 = &DAT_802caed0;
  for (iVar15 = 0;
      iVar15 < (int)((uint3)(CONCAT12(uVar4,CONCAT11(uVar3,uVar8)) >> (uVar13 & 7)) & 0xf);
      iVar15 = iVar15 + 1) {
    uVar12 = param_3[4];
    puVar14 = (undefined *)(*param_3 + ((int)uVar12 >> 3));
    uVar5 = *puVar14;
    uVar6 = puVar14[1];
    uVar7 = puVar14[2];
    param_3[4] = uVar12 + 8;
    if (DAT_803dcc48 == 2) {
      FUN_8025d0a8(iVar9 + ((uint3)(CONCAT12(uVar7,CONCAT11(uVar6,uVar5)) >> (uVar12 & 7)) & 0xff) *
                           0x30,*puVar17);
    }
    else {
      uVar11 = FUN_8002856c((int)uVar18);
      FUN_80246eb4(param_4,uVar11,auStack88);
      FUN_8025d0a8(auStack88,*puVar17);
    }
    puVar17 = puVar17 + 1;
  }
  FUN_8028611c();
  return;
}

