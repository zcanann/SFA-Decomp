// Function: FUN_80240d8c
// Entry: 80240d8c
// Size: 592 bytes

void FUN_80240d8c(undefined4 *param_1,undefined4 param_2,uint param_3,uint param_4,
                 undefined4 param_5)

{
  ulonglong uVar1;
  uint uVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  bool bVar7;
  undefined8 uVar8;
  longlong lVar9;
  
  if (0x80000000 < (uint)(param_1[7] != 0) + (param_1[6] ^ 0x80000000)) {
    uVar8 = FUN_80246c70();
    uVar2 = (uint)((ulonglong)uVar8 >> 0x20);
    uVar4 = (uint)uVar8;
    param_3 = param_1[8];
    param_4 = param_1[9];
    if ((param_3 ^ 0x80000000) < (uint)(param_4 < uVar4) + (uVar2 ^ 0x80000000)) {
      iVar6 = param_1[6];
      uVar5 = param_1[7];
      lVar9 = FUN_8028622c(uVar2 - ((uVar4 < param_4) + param_3),uVar4 - param_4,iVar6,uVar5);
      uVar1 = lVar9 + 1;
      uVar2 = uVar5 * (int)uVar1;
      bVar7 = CARRY4(param_4,uVar2);
      param_4 = param_4 + uVar2;
      param_3 = param_3 + iVar6 * (int)uVar1 +
                          (int)((ulonglong)uVar5 * (uVar1 & 0xffffffff) >> 0x20) +
                          uVar5 * (int)(uVar1 >> 0x20) + (uint)bVar7;
    }
  }
  *param_1 = param_5;
  param_1[3] = param_4;
  param_1[2] = param_3;
  puVar3 = DAT_803dde08;
  while( true ) {
    if (puVar3 == (undefined4 *)0x0) {
      param_1[5] = 0;
      iVar6 = (int)puRam803dde0c;
      bVar7 = puRam803dde0c == (undefined4 *)0x0;
      puVar3 = param_1;
      param_1[4] = puRam803dde0c;
      puRam803dde0c = puVar3;
      if (bVar7) {
        DAT_803dde08 = param_1;
        puRam803dde0c = param_1;
        uVar8 = FUN_80246c70();
        uVar4 = param_1[3] - (uint)uVar8;
        uVar2 = param_1[2] -
                ((uint)((uint)param_1[3] < (uint)uVar8) + (int)((ulonglong)uVar8 >> 0x20)) ^
                0x80000000;
        if (uVar2 < 0x80000000) {
          FUN_80294640(0);
        }
        else if (uVar2 < (uVar4 < 0x80000000) + 0x80000000) {
          FUN_80294640(uVar4);
        }
        else {
          FUN_80294640(0x7fffffff);
        }
      }
      else {
        *(undefined4 **)(iVar6 + 0x14) = param_1;
      }
      return;
    }
    if ((param_3 ^ 0x80000000) < (uint)(param_4 < (uint)puVar3[3]) + (puVar3[2] ^ 0x80000000))
    break;
    puVar3 = (undefined4 *)puVar3[5];
  }
  param_1[4] = puVar3[4];
  puVar3[4] = param_1;
  param_1[5] = puVar3;
  if (param_1[4] != 0) {
    *(undefined4 **)(param_1[4] + 0x14) = param_1;
    return;
  }
  DAT_803dde08 = param_1;
  uVar8 = FUN_80246c70();
  uVar4 = param_1[3] - (uint)uVar8;
  uVar2 = param_1[2] - ((uint)((uint)param_1[3] < (uint)uVar8) + (int)((ulonglong)uVar8 >> 0x20)) ^
          0x80000000;
  if (uVar2 < 0x80000000) {
    FUN_80294640(0);
    return;
  }
  if (uVar2 < (uVar4 < 0x80000000) + 0x80000000) {
    FUN_80294640(uVar4);
    return;
  }
  FUN_80294640(0x7fffffff);
  return;
}

