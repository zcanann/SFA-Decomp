// Function: FUN_8013012c
// Entry: 8013012c
// Size: 248 bytes

void FUN_8013012c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  short *psVar6;
  
  DAT_803de516 = 0xff;
  DAT_803de514 = 0xffff;
  DAT_803de542 = 0xffff;
  DAT_803de538 = 0;
  DAT_803de4b0 = 0xffff;
  uVar1 = FUN_80070050();
  iVar3 = (int)uVar1 >> 0x10;
  DAT_803de3c4 = (uVar1 & 0xffff) - 0x140;
  DAT_803de3c0 = iVar3 + -0xf0;
  iVar4 = 0;
  psVar6 = &DAT_8031c274;
  puVar5 = &DAT_803a9610;
  do {
    uVar2 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*psVar6,iVar3,param_11,param_12,param_13,param_14,param_15,param_16);
    *puVar5 = uVar2;
    psVar6 = psVar6 + 1;
    puVar5 = puVar5 + 1;
    iVar4 = iVar4 + 1;
  } while (iVar4 < 0x66);
  DAT_803de544 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x500,
                              iVar3,param_11,param_12,param_13,param_14,param_15,param_16);
  *(undefined2 *)(DAT_803de544 + 0x14) = 0x28;
  DAT_803de4ac = 0x80000;
  DAT_803de4a8 = 0;
  DAT_803a9ffc = 0xffffffff;
  DAT_803aa004 = 0;
  DAT_803a9ff8 = 0;
  DAT_803aa000 = FLOAT_803e2abc;
  DAT_803de504 = 0;
  DAT_803de450 = 0;
  return;
}

