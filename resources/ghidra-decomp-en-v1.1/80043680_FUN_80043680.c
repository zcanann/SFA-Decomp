// Function: FUN_80043680
// Entry: 80043680
// Size: 476 bytes

void FUN_80043680(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined *puVar7;
  undefined *puVar8;
  undefined8 uVar9;
  longlong lVar10;
  
  lVar10 = FUN_8028683c();
  iVar4 = (int)((ulonglong)lVar10 >> 0x20);
  iVar5 = (int)lVar10;
  iVar3 = 0;
  puVar7 = (undefined *)0x0;
  bVar1 = false;
  uVar6 = 0;
  puVar8 = puVar7;
  if (iVar4 != 0x25) {
    if (lVar10 < 0x2500000000) {
      if (iVar4 == 0x1a) {
        iVar3 = 0x800;
        puVar8 = &DAT_8034ec70;
      }
      else if (lVar10 < 0x1a00000000) {
        if (iVar4 == 0xe) {
          iVar3 = 0x1fd0;
          uVar6 = 0xa0000000;
          puVar8 = &DAT_80346d30;
        }
      }
      else if (iVar4 == 0x21) {
        iVar3 = 0x1000;
        puVar8 = &DAT_80352c70;
      }
      else if ((0x20ffffffff < lVar10) && (0x23ffffffff < lVar10)) {
        iVar3 = 0x1000;
        puVar8 = &DAT_80356c70;
      }
    }
    else if (iVar4 == 0x2f) {
      iVar3 = 3000;
      puVar8 = &DAT_8035ac70;
    }
    else if (lVar10 < 0x2f00000000) {
      if (iVar4 == 0x2a) {
        iVar3 = 0x800;
        uVar6 = 0xc;
        puVar8 = &DAT_8035db50;
      }
      else if ((lVar10 < 0x2a00000000) && (lVar10 < 0x2700000000)) {
        iVar3 = 0x800;
        puVar8 = &DAT_80350c70;
      }
    }
    else {
      puVar8 = DAT_80360188;
      if (iVar4 != 0x50) {
        puVar8 = puVar7;
      }
    }
  }
  if ((-1 < iVar5) && (iVar5 < iVar3)) {
    while( true ) {
      FUN_80243e74();
      uVar2 = DAT_803dd900;
      FUN_80243e9c();
      if ((uVar6 & uVar2) == 0) break;
      uVar9 = FUN_80014f6c();
      FUN_80020390();
      if (bVar1) {
        uVar9 = FUN_8004a9e4();
      }
      uVar9 = FUN_80048350(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_80015650(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      if (bVar1) {
        uVar9 = FUN_800235b0();
        FUN_80019c5c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        FUN_8004a5b8('\x01');
      }
      if (DAT_803dd5d0 != '\0') {
        bVar1 = true;
      }
    }
    if (puVar8 != (undefined *)0x0) {
      *param_11 = *(undefined4 *)(puVar8 + iVar5 * 4);
    }
  }
  FUN_80286888();
  return;
}

