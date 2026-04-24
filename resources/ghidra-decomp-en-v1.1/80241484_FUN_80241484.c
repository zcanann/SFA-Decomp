// Function: FUN_80241484
// Entry: 80241484
// Size: 592 bytes

void FUN_80241484(undefined4 *param_1,undefined4 param_2,uint param_3,uint param_4,
                 undefined4 param_5)

{
  ulonglong uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 *puVar5;
  uint uVar6;
  uint uVar7;
  bool bVar8;
  longlong lVar9;
  
  if (0x80000000 < (uint)(param_1[7] != 0) + (param_1[6] ^ 0x80000000)) {
    lVar9 = FUN_802473d4();
    uVar3 = (uint)((ulonglong)lVar9 >> 0x20);
    uVar4 = (uint)lVar9;
    param_3 = param_1[8];
    param_4 = param_1[9];
    if ((param_3 ^ 0x80000000) < (uint)(param_4 < uVar4) + (uVar3 ^ 0x80000000)) {
      uVar7 = param_1[6];
      uVar6 = param_1[7];
      lVar9 = FUN_80286990(uVar3 - ((uVar4 < param_4) + param_3),uVar4 - param_4,uVar7,uVar6);
      uVar1 = lVar9 + 1;
      uVar3 = uVar6 * (int)uVar1;
      bVar8 = CARRY4(param_4,uVar3);
      param_4 = param_4 + uVar3;
      param_3 = param_3 + uVar7 * (int)uVar1 +
                          (int)((ulonglong)uVar6 * (uVar1 & 0xffffffff) >> 0x20) +
                          uVar6 * (int)(uVar1 >> 0x20) + (uint)bVar8;
    }
  }
  *param_1 = param_5;
  param_1[3] = param_4;
  param_1[2] = param_3;
  puVar5 = DAT_803dea88;
  while( true ) {
    if (puVar5 == (undefined4 *)0x0) {
      param_1[5] = 0;
      iVar2 = (int)puRam803dea8c;
      bVar8 = puRam803dea8c == (undefined4 *)0x0;
      puVar5 = param_1;
      param_1[4] = puRam803dea8c;
      puRam803dea8c = puVar5;
      if (bVar8) {
        DAT_803dea88 = param_1;
        puRam803dea8c = param_1;
        lVar9 = FUN_802473d4();
        uVar3 = param_1[2] -
                ((uint)((uint)param_1[3] < (uint)lVar9) + (int)((ulonglong)lVar9 >> 0x20)) ^
                0x80000000;
        if (uVar3 < 0x80000000) {
          FUN_80294da0();
        }
        else if (uVar3 < (param_1[3] - (uint)lVar9 < 0x80000000) + 0x80000000) {
          FUN_80294da0();
        }
        else {
          FUN_80294da0();
        }
      }
      else {
        *(undefined4 **)(iVar2 + 0x14) = param_1;
      }
      return;
    }
    if ((param_3 ^ 0x80000000) < (uint)(param_4 < (uint)puVar5[3]) + (puVar5[2] ^ 0x80000000))
    break;
    puVar5 = (undefined4 *)puVar5[5];
  }
  param_1[4] = puVar5[4];
  puVar5[4] = param_1;
  param_1[5] = puVar5;
  if (param_1[4] != 0) {
    *(undefined4 **)(param_1[4] + 0x14) = param_1;
    return;
  }
  DAT_803dea88 = param_1;
  lVar9 = FUN_802473d4();
  uVar3 = param_1[2] - ((uint)((uint)param_1[3] < (uint)lVar9) + (int)((ulonglong)lVar9 >> 0x20)) ^
          0x80000000;
  if (uVar3 < 0x80000000) {
    FUN_80294da0();
    return;
  }
  if (uVar3 < (param_1[3] - (uint)lVar9 < 0x80000000) + 0x80000000) {
    FUN_80294da0();
    return;
  }
  FUN_80294da0();
  return;
}

