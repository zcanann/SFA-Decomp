// Function: FUN_80131574
// Entry: 80131574
// Size: 640 bytes

void FUN_80131574(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined param_11,undefined *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16,
                 undefined2 param_17,undefined2 param_18,undefined2 param_19,undefined2 param_20)

{
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint extraout_r4;
  int iVar6;
  undefined *puVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  int iVar10;
  uint uVar11;
  undefined2 *puVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286824();
  uVar11 = (uint)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  if (iVar4 < 0x29) {
    DAT_803de591 = (undefined)uVar13;
    DAT_803de58e = 0xff;
    DAT_803de590 = 0;
    DAT_803de593 = 0;
    iVar6 = iVar4 * 0x3c;
    puVar7 = param_12;
    uVar8 = param_15;
    uVar9 = param_16;
    DAT_803de592 = param_11;
    uVar13 = FUN_80003494(0x803aa0b8,uVar11,iVar6);
    puVar12 = &DAT_803aa0b8;
    for (iVar10 = 0; iVar10 < iVar4; iVar10 = iVar10 + 1) {
      if ((*(char *)(puVar12 + 0xd) < -1) || (iVar4 <= *(char *)(puVar12 + 0xd))) {
        uVar13 = FUN_8007d858();
      }
      if ((*(char *)((int)puVar12 + 0x1b) < -1) || (iVar4 <= *(char *)((int)puVar12 + 0x1b))) {
        uVar13 = FUN_8007d858();
      }
      if ((*(char *)(puVar12 + 0xe) < -1) || (iVar4 <= *(char *)(puVar12 + 0xe))) {
        uVar13 = FUN_8007d858();
      }
      bVar1 = *(byte *)((int)puVar12 + 0x1d);
      uVar5 = (uint)bVar1;
      if (((char)bVar1 < -1) || (iVar4 <= (char)bVar1)) {
        uVar13 = FUN_8007d858();
        uVar5 = extraout_r4;
      }
      if (*(int *)(uVar11 + 0x10) == -1) {
        *(undefined4 *)(puVar12 + 8) = 0;
      }
      else {
        uVar2 = FUN_80054ed0(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                             *(int *)(uVar11 + 0x10),uVar5,iVar6,puVar7,param_13,param_14,uVar8,
                             uVar9);
        *(undefined4 *)(puVar12 + 8) = uVar2;
      }
      if ((puVar12[0xb] & 0x10) != 0) {
        puVar12[10] = 0;
        puVar12[4] = 0;
      }
      if ((puVar12[0xb] & 4) != 0) {
        uVar13 = FUN_8013049c((int)puVar12);
      }
      iVar3 = (int)*(char *)(puVar12 + 0xe);
      if ((iVar3 != -1) && ((puVar12[0xb] & 8) != 0)) {
        puVar12[5] = (&DAT_803aa0c2)[iVar3 * 0x1e] + (&DAT_803aa0cc)[iVar3 * 0x1e];
        puVar12[2] = (&DAT_803aa0bc)[iVar3 * 0x1e] + (&DAT_803aa0cc)[iVar3 * 0x1e];
      }
      if ((puVar12[0xb] & 0x400) != 0) {
        puVar12[5] = puVar12[5] - (short)((int)(uint)(ushort)puVar12[10] >> 1);
        puVar12[2] = puVar12[5];
      }
      *(undefined *)(puVar12 + 0x1c) = 4;
      puVar12 = puVar12 + 0x1e;
      uVar11 = uVar11 + 0x3c;
    }
    DAT_803de584 = (undefined2)param_15;
    DAT_803de582 = (undefined2)param_16;
    DAT_803de580 = param_17;
    DAT_803de57e = param_18;
    DAT_803de57c = param_19;
    DAT_803de57a = param_20;
    DAT_803de588 = &DAT_8031cdf8;
    if (param_12 != (undefined *)0x0) {
      DAT_803de588 = param_12;
    }
  }
  FUN_80286870();
  return;
}

