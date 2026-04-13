// Function: FUN_8011c180
// Entry: 8011c180
// Size: 300 bytes

void FUN_8011c180(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 extraout_r4;
  int iVar2;
  int *piVar3;
  int *piVar4;
  ushort *puVar5;
  float local_28 [2];
  undefined8 local_20;
  
  DAT_803de36c = 2;
  DAT_803de36d = 2;
  DAT_803de374 = 0;
  DAT_803de370 = 0;
  DAT_803de368 = 0;
  iVar2 = 0;
  puVar5 = &DAT_8031b4d0;
  piVar4 = &DAT_803a9390;
  piVar3 = &DAT_803a92f0;
  do {
    uVar1 = FUN_8001947c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (uint)*puVar5,param_10,param_11,param_12,param_13,param_14,param_15,
                         param_16);
    param_12 = 0;
    param_13 = 0;
    param_14 = 0xffffffff;
    param_1 = FUN_80018728(uVar1,local_28,(undefined4 *)0x0,(float *)0x0,(float *)0x0,0xffffffff);
    local_20 = (double)(longlong)(int)local_28[0];
    *piVar4 = (int)local_28[0];
    *piVar3 = DAT_803de368;
    param_11 = DAT_803de368 + *piVar4;
    puVar5 = puVar5 + 1;
    piVar4 = piVar4 + 1;
    piVar3 = piVar3 + 1;
    iVar2 = iVar2 + 1;
    param_10 = extraout_r4;
    DAT_803de368 = param_11;
  } while (iVar2 < 0x28);
  DAT_803de364 = 0;
  local_20 = (double)CONCAT44(0x43300000,DAT_803a9390 / 2 ^ 0x80000000);
  FLOAT_803de360 = (float)(local_20 - DOUBLE_803e2a28);
  DAT_803de35a = 0;
  DAT_803de35c = param_11;
  FUN_8000bb38(0,0x418);
  return;
}

