// Function: FUN_8007f918
// Entry: 8007f918
// Size: 432 bytes

void FUN_8007f918(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined *puVar1;
  int iVar2;
  undefined8 uVar3;
  
  iVar2 = FUN_80019c30();
  if (iVar2 == 4) {
    *DAT_803ddcdc = 0x83;
    DAT_803ddcdc[1] = 0x58;
    DAT_803ddcdc[2] = 0x83;
    DAT_803ddcdc[3] = 0x5e;
    DAT_803ddcdc[4] = 0x81;
    DAT_803ddcdc[5] = 0x5b;
    DAT_803ddcdc[6] = 0x83;
    DAT_803ddcdc[7] = 0x74;
    DAT_803ddcdc[8] = 0x83;
    DAT_803ddcdc[9] = 0x48;
    DAT_803ddcdc[10] = 0x83;
    DAT_803ddcdc[0xb] = 0x62;
    DAT_803ddcdc[0xc] = 0x83;
    DAT_803ddcdc[0xd] = 0x4e;
    DAT_803ddcdc[0xe] = 0x83;
    DAT_803ddcdc[0xf] = 0x58;
    DAT_803ddcdc[0x10] = 0x83;
    DAT_803ddcdc[0x11] = 0x41;
    DAT_803ddcdc[0x12] = 0x83;
    DAT_803ddcdc[0x13] = 0x68;
    DAT_803ddcdc[0x14] = 0x83;
    DAT_803ddcdc[0x15] = 0x78;
    DAT_803ddcdc[0x16] = 0x83;
    DAT_803ddcdc[0x17] = 0x93;
    DAT_803ddcdc[0x18] = 0x83;
    DAT_803ddcdc[0x19] = 0x60;
    DAT_803ddcdc[0x1a] = 0x83;
    puVar1 = DAT_803ddcdc;
    DAT_803ddcdc[0x1b] = 0x83;
    DAT_803ddcdc[0x1c] = 0x81;
    DAT_803ddcdc[0x1d] = 0x5b;
    DAT_803ddcdc[0x1e] = 0;
    DAT_803ddcdc[0x1f] = 0;
    FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(DAT_803ddcdc + 0x20),s_STARFOX_ADVENTURES_8030f79c,puVar1,0x60,0x58,param_14,
                 param_15,param_16);
  }
  else {
    uVar3 = FUN_8028fde8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)DAT_803ddcdc,s_Star_Fox_Adventures_8030f678,param_11,param_12,param_13
                         ,param_14,param_15,param_16);
    FUN_8028fde8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 (int)(DAT_803ddcdc + 0x20),s_Dinosaur_Planet_8030f7b0,param_11,param_12,param_13,
                 param_14,param_15,param_16);
  }
  return;
}

