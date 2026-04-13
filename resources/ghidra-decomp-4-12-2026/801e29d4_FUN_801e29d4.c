// Function: FUN_801e29d4
// Entry: 801e29d4
// Size: 388 bytes

void FUN_801e29d4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 extraout_r4;
  undefined4 uVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  DAT_803de8a0 = param_9;
  FUN_800372f8((int)param_9,3);
  uVar3 = FUN_8002b9a0((int)param_9,'Z');
  *(code **)(param_9 + 0x5e) = FUN_801e209c;
  *(undefined4 *)(iVar2 + 0x2c) = *(undefined4 *)(param_9 + 6);
  *(undefined4 *)(iVar2 + 0x30) = *(undefined4 *)(param_9 + 8);
  *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(param_9 + 10);
  *(undefined *)(iVar2 + 0x2a) = 1;
  *(undefined2 *)(iVar2 + 0x26) = 0xf0;
  *(undefined2 *)(iVar2 + 0x6e) = 0xf0;
  *(undefined *)(iVar2 + 0x79) = 0;
  *(undefined2 *)(iVar2 + 0x82) = 200;
  *(undefined *)(iVar2 + 0xa7) = 0x89;
  *(undefined *)(iVar2 + 0xa8) = 0x95;
  *(undefined *)(iVar2 + 0xa9) = 0x86;
  *(undefined *)(iVar2 + 0xaa) = 0x88;
  *(undefined *)(iVar2 + 0xa5) = 0x87;
  *(undefined *)(iVar2 + 0xa6) = 0x97;
  *(short *)(iVar2 + 0x72) = (short)*(char *)(param_9 + 0x56);
  *param_9 = 0x4000;
  param_9[1] = 0;
  param_9[2] = 0;
  uVar1 = extraout_r4;
  DAT_803de898 = FUN_80054ed0(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x16d,
                              extraout_r4,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de89c = FUN_80054ed0(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x89,
                              uVar1,param_11,param_12,param_13,param_14,param_15,param_16);
  *(undefined *)(iVar2 + 0x84) = 100;
  uVar3 = (**(code **)(*DAT_803dd72c + 0x44))((int)*(char *)(param_9 + 0x56),1);
  FUN_800066e0(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x58,0,
               0,0,param_15,param_16);
  *(float *)(iVar2 + 0x90) = FLOAT_803e6364;
  *(float *)(iVar2 + 0x94) = FLOAT_803e64a4;
  *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) =
       *(ushort *)(*(int *)(param_9 + 0x2a) + 0x60) | 0x1800;
  FUN_8005cf74(0);
  *(undefined4 *)(iVar2 + 0x98) = 0x92;
  *(undefined4 *)(iVar2 + 0x9c) = 0x91;
  FUN_8000a538(*(int **)(iVar2 + 0x9c),1);
  return;
}

