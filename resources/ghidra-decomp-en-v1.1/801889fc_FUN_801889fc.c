// Function: FUN_801889fc
// Entry: 801889fc
// Size: 216 bytes

void FUN_801889fc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  ushort *puVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_9 + 0x5c);
  *(undefined **)(param_9 + 0x5e) = &LAB_801888f0;
  if (DAT_803225f0 == 0) {
    DAT_803225f0 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                0x268,param_10,param_11,param_12,param_13,param_14,param_15,param_16
                               );
  }
  puVar2[2] = &DAT_803225e0;
  puVar1 = FUN_800195a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                        (uint)*(ushort *)(param_10 + 0x18));
  puVar2[1] = **(undefined4 **)(puVar1 + 4);
  puVar2[3] = 100;
  *puVar2 = puVar1;
  *param_9 = (ushort)*(byte *)(param_10 + 0x1c) << 8;
  puVar2[6] = 2;
  *(undefined *)(puVar2 + 4) = *(undefined *)(param_10 + 0x1b);
  *(undefined2 *)((int)puVar2 + 0x16) = 0;
  param_9[0x58] = param_9[0x58] | 0x2000;
  return;
}

