// Function: FUN_801e23e4
// Entry: 801e23e4
// Size: 388 bytes

void FUN_801e23e4(undefined2 *param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  DAT_803ddc20 = param_1;
  FUN_80037200(param_1,3);
  FUN_8002b8c8(param_1,0x5a);
  *(code **)(param_1 + 0x5e) = FUN_801e1aac;
  *(undefined4 *)(iVar1 + 0x2c) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(iVar1 + 0x30) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(iVar1 + 0x34) = *(undefined4 *)(param_1 + 10);
  *(undefined *)(iVar1 + 0x2a) = 1;
  *(undefined2 *)(iVar1 + 0x26) = 0xf0;
  *(undefined2 *)(iVar1 + 0x6e) = 0xf0;
  *(undefined *)(iVar1 + 0x79) = 0;
  *(undefined2 *)(iVar1 + 0x82) = 200;
  *(undefined *)(iVar1 + 0xa7) = 0x89;
  *(undefined *)(iVar1 + 0xa8) = 0x95;
  *(undefined *)(iVar1 + 0xa9) = 0x86;
  *(undefined *)(iVar1 + 0xaa) = 0x88;
  *(undefined *)(iVar1 + 0xa5) = 0x87;
  *(undefined *)(iVar1 + 0xa6) = 0x97;
  *(short *)(iVar1 + 0x72) = (short)*(char *)(param_1 + 0x56);
  *param_1 = 0x4000;
  param_1[1] = 0;
  param_1[2] = 0;
  DAT_803ddc18 = FUN_80054d54(0x16d);
  DAT_803ddc1c = FUN_80054d54(0x89);
  *(undefined *)(iVar1 + 0x84) = 100;
  (**(code **)(*DAT_803dcaac + 0x44))((int)*(char *)(param_1 + 0x56),1);
  FUN_800066e0(param_1,param_1,0x58,0,0,0);
  *(float *)(iVar1 + 0x90) = FLOAT_803e56cc;
  *(float *)(iVar1 + 0x94) = FLOAT_803e580c;
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 0x1800;
  FUN_8005cdf8(0);
  *(undefined4 *)(iVar1 + 0x98) = 0x92;
  *(undefined4 *)(iVar1 + 0x9c) = 0x91;
  FUN_8000a518(*(undefined4 *)(iVar1 + 0x9c),1);
  return;
}

