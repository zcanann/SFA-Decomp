// Function: FUN_8006fe48
// Entry: 8006fe48
// Size: 300 bytes

void FUN_8006fe48(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 *puVar1;
  undefined *puVar2;
  int iVar3;
  
  puVar1 = &DAT_80393a40;
  puVar2 = &DAT_80392a40;
  iVar3 = 0x10;
  do {
    *(undefined *)((int)puVar1 + 0x33) = 0;
    puVar2[0xe] = 0;
    *(undefined *)((int)puVar1 + 0x6b) = 0;
    puVar2[0x1e] = 0;
    *(undefined *)((int)puVar1 + 0xa3) = 0;
    puVar2[0x2e] = 0;
    *(undefined *)((int)puVar1 + 0xdb) = 0;
    puVar2[0x3e] = 0;
    *(undefined *)((int)puVar1 + 0x113) = 0;
    puVar2[0x4e] = 0;
    *(undefined *)((int)puVar1 + 0x14b) = 0;
    puVar2[0x5e] = 0;
    *(undefined *)((int)puVar1 + 0x183) = 0;
    puVar2[0x6e] = 0;
    *(undefined *)((int)puVar1 + 0x1bb) = 0;
    puVar2[0x7e] = 0;
    *(undefined *)((int)puVar1 + 499) = 0;
    puVar2[0x8e] = 0;
    *(undefined *)((int)puVar1 + 0x22b) = 0;
    puVar2[0x9e] = 0;
    *(undefined *)((int)puVar1 + 0x263) = 0;
    puVar2[0xae] = 0;
    *(undefined *)((int)puVar1 + 0x29b) = 0;
    puVar2[0xbe] = 0;
    *(undefined *)((int)puVar1 + 0x2d3) = 0;
    puVar2[0xce] = 0;
    *(undefined *)((int)puVar1 + 0x30b) = 0;
    puVar2[0xde] = 0;
    *(undefined *)((int)puVar1 + 0x343) = 0;
    puVar2[0xee] = 0;
    *(undefined *)((int)puVar1 + 0x37b) = 0;
    puVar2[0xfe] = 0;
    puVar1 = puVar1 + 0xe0;
    puVar2 = puVar2 + 0x100;
    iVar3 = iVar3 + -1;
  } while (iVar3 != 0);
  DAT_80392a30 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x19,
                              puVar2,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_80392a34 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x18,
                              puVar2,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_80392a38 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x1a,
                              puVar2,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_80392a3c = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x646,
                              puVar2,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_80392a20 = FLOAT_803dfadc;
  DAT_80392a24 = FLOAT_803dfae0;
  DAT_80392a28 = FLOAT_803dfae0;
  DAT_80392a2c = FLOAT_803dfae4;
  DAT_803ddc7a = 0;
  DAT_803ddc79 = 0;
  DAT_803ddc78 = 0;
  DAT_803ddc74 = 0;
  return;
}

