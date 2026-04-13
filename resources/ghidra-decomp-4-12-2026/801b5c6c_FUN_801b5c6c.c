// Function: FUN_801b5c6c
// Entry: 801b5c6c
// Size: 260 bytes

void FUN_801b5c6c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  undefined4 extraout_r4;
  undefined4 uVar2;
  int iVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  double dVar6;
  double dVar7;
  undefined4 local_28 [7];
  
  local_28[0] = DAT_802c2aa8;
  local_28[1] = DAT_802c2aac;
  local_28[2] = DAT_802c2ab0;
  local_28[3] = DAT_802c2ab4;
  dVar6 = (double)FUN_80292538();
  FLOAT_803de7f0 = (float)((double)FLOAT_803e55c4 / dVar6);
  dVar6 = (double)FUN_80292538();
  FLOAT_803de7ec = (float)((double)FLOAT_803e55c4 / dVar6);
  dVar6 = (double)FUN_80292538();
  FLOAT_803de7e8 = (float)((double)FLOAT_803e55c4 / dVar6);
  dVar6 = (double)FUN_80292538();
  FLOAT_803de7e4 = (float)((double)FLOAT_803e55c4 / dVar6);
  dVar6 = (double)FUN_80292538();
  dVar7 = (double)FLOAT_803e55c4;
  FLOAT_803de7e0 = (float)(dVar7 / dVar6);
  dVar6 = (double)FUN_80292538();
  FLOAT_803de7dc = (float)((double)FLOAT_803e55c4 / dVar6);
  iVar3 = 0;
  puVar5 = local_28;
  puVar4 = &DAT_803ad5c0;
  uVar2 = extraout_r4;
  do {
    uVar1 = FUN_80054ed0(dVar6,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,*puVar5,uVar2,
                         param_11,param_12,param_13,param_14,param_15,param_16);
    *puVar4 = uVar1;
    puVar5 = puVar5 + 1;
    puVar4 = puVar4 + 1;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 4);
  return;
}

