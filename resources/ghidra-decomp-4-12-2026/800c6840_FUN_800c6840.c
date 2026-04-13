// Function: FUN_800c6840
// Entry: 800c6840
// Size: 6724 bytes

void FUN_800c6840(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  ushort *puVar1;
  uint uVar2;
  undefined8 uVar3;
  ushort local_d8;
  ushort local_d6;
  ushort local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  ushort *local_c0;
  undefined4 local_bc;
  uint local_b8;
  ushort local_b4;
  ushort local_b2;
  ushort local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  short local_7e;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  uint local_70;
  uint local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  byte local_60;
  undefined local_5f;
  undefined local_5e;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar3 = FUN_8028683c();
  puVar1 = (ushort *)((ulonglong)uVar3 >> 0x20);
  if (puVar1 != (ushort *)0x0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800c826c;
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_ac = *(float *)(param_3 + 4);
      local_b0 = param_3[2];
      local_b2 = param_3[1];
      local_b4 = *param_3;
      local_5e = param_5;
    }
    local_7c = 0;
    local_78 = 0;
    local_62 = (undefined)uVar3;
    local_90 = FLOAT_803e0c80;
    local_8c = FLOAT_803e0c80;
    local_88 = FLOAT_803e0c80;
    local_9c = FLOAT_803e0c80;
    local_98 = FLOAT_803e0c80;
    local_94 = FLOAT_803e0c80;
    local_84 = FLOAT_803e0c80;
    local_b8 = 0;
    local_bc = 0xffffffff;
    local_60 = 0xff;
    local_5f = 0;
    local_7e = 0;
    local_68 = 0xffff;
    local_66 = 0xffff;
    local_64 = 0xffff;
    local_74 = 0xffff;
    local_70 = 0xffff;
    local_6c = 0xffff;
    local_c0 = puVar1;
    switch((int)uVar3) {
    case 0x4b0:
      if (param_6 == (float *)0x0) goto LAB_800c826c;
      uStack_54 = (int)(uint)*(ushort *)param_6 >> 1 & 0xff;
      local_60 = (byte)((int)(uint)*(ushort *)param_6 >> 1);
      local_58 = 0x43300000;
      local_84 = FLOAT_803e0c84 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d18);
      local_b8 = 1;
      local_7c = 0x80000;
      local_78 = 0x800;
      local_7e = 0xc7e;
      break;
    case 0x4b1:
      uStack_54 = FUN_80022264(0xffffff9c,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0c88 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d20);
      uStack_4c = FUN_80022264(0xffffffe7,0x96);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e0c88 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      local_b8 = 100;
      local_84 = FLOAT_803e0c90;
      local_7c = 0x1180200;
      local_7e = 0x167;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0;
      local_78 = 0x20;
      break;
    case 0x4b2:
      local_b8 = 0x46;
      local_84 = FLOAT_803e0c94;
      local_7c = 0x100100;
      local_7e = 0x73;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0xff00;
      local_78 = 0x20;
      local_60 = 0x7f;
      break;
    case 0x4b3:
      local_b8 = 0x23;
      local_84 = FLOAT_803e0c98;
      local_7c = 0x100200;
      local_78 = 0x4000800;
      local_7e = 0x73;
      break;
    case 0x4b4:
      uStack_44 = FUN_80022264(0xffffffff,1);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80022264(0xfffffff9,7);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      uStack_54 = FUN_80022264(0xffffffff,1);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0xfffffff9,7);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xfffffff9,7);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_24 = FUN_80022264(0x32,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e0c9c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uVar2 = FUN_80022264(0x5c,0xc0);
      local_60 = (byte)uVar2;
      local_b8 = FUN_80022264(0x32,0x50);
      local_7c = 0x1180000;
      local_78 = 0x4400820;
      local_7e = 0x30;
      local_68 = 0;
      uVar2 = FUN_80022264(0,0xffff);
      local_66 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_64 = (undefined2)uVar2;
      local_74 = 0;
      local_70 = 0xff00;
      local_6c = FUN_80022264(0,0xffff);
      break;
    case 0x4b5:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_84 = FLOAT_803e0ca0;
      local_b8 = 0x5f;
      local_7c = 0x1180200;
      local_78 = 0x4000820;
      local_7e = 0x62;
      local_68 = 0;
      uVar2 = FUN_80022264(0x8000,0xffff);
      local_66 = (undefined2)uVar2;
      local_64 = 0;
      local_74 = FUN_80022264(0,0x8000);
      local_70 = FUN_80022264(0,0xffff);
      local_6c = 0;
      break;
    case 0x4b6:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_60 = 0x40;
      local_84 = FLOAT_803e0ca4;
      local_b8 = 0x32;
      local_7c = 0x180110;
      local_78 = 0x4000800;
      local_7e = 0x62;
      break;
    case 0x4b7:
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = FLOAT_803e0ca8;
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0c8c;
      local_b8 = 0x28;
      local_7c = 0x80200;
      local_7e = 0x5f;
      local_60 = 0x3f;
      break;
    case 0x4b8:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_b8 = 0x25;
      local_84 = FLOAT_803e0cac;
      local_7c = 0x80200;
      local_78 = 0x4000800;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_7e = 0xc0e;
      }
      else {
        uVar2 = FUN_80022264(0x156,0x157);
        local_7e = (short)uVar2;
      }
      break;
    default:
      goto LAB_800c826c;
    case 0x4ba:
      uStack_24 = FUN_80022264(0xfffffff9,7);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xfffffff9,7);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xfffffff9,7);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0ca4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80022264(0xffffffce,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e0ca4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80022264(0xffffffce,0x32);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0ca4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0c8c;
      local_b8 = 0x28;
      local_60 = 0x96;
      local_7c = 0x1080200;
      local_7e = 0x62;
      local_68 = 0;
      local_66 = 0xffff;
      local_64 = 0;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0x7fff;
      local_78 = 0x4000820;
      break;
    case 0x4bb:
      local_b8 = 0x24;
      local_84 = FLOAT_803e0cb0;
      local_7c = 0x100200;
      local_7e = 0x27;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0xff00;
      local_74 = 0;
      local_70 = 0xff00;
      local_6c = 0;
      local_78 = 0x4000820;
      break;
    case 0x4bc:
      if (param_6 == (float *)0x0) goto LAB_800c826c;
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack_2c = (uint)local_60;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0cb4 *
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack_3c = (uint)local_60;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0cb4 *
                 (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack_4c = (uint)local_60;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e0cb4 *
                 (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d18) *
                 (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_54 = (uint)*param_6 & 0xff;
      local_60 = SUB41(*param_6,0);
      local_58 = 0x43300000;
      local_84 = FLOAT_803e0cb8 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0d18)
                 + FLOAT_803e0cb8;
      local_b8 = FUN_80022264(0xf,0x1e);
      local_7c = 0xc1080100;
      local_78 = 0x800;
      local_7e = 0xdb;
      break;
    case 0x4bd:
      uStack_24 = FUN_80022264(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0,0xf);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_98 = FLOAT_803e0cbc;
      uStack_3c = FUN_80022264(5,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0cc0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_b8 = FUN_80022264(0x3c,0x5a);
      local_60 = 0x5a;
      local_7c = 0xc0180200;
      local_7e = 0x5f;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0x8000;
      local_78 = 0x4000820;
      break;
    case 0x4be:
      uStack_24 = FUN_80022264(0xfffffe3e,0x1c2);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = FLOAT_803e0cc4;
      uStack_2c = FUN_80022264(0xfffffe3e,0x1c2);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e0cc8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uStack_44 = FUN_80022264(0xffffffec,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80022264(0,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = FLOAT_803e0cd0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20)
                 + FLOAT_803e0ccc;
      local_b8 = FUN_80022264(0xbe,0xfa);
      local_7c = 0x81488000;
      uVar2 = FUN_80022264(0,2);
      local_7e = (short)uVar2 + 0x208;
      local_68 = 0x2000;
      local_66 = 0x8000;
      local_64 = 0xc000;
      local_74 = 0xc000;
      local_70 = 0xff00;
      local_6c = 0xff00;
      local_78 = 0x20;
      break;
    case 0x4bf:
      uStack_24 = FUN_80022264(0xffffff92,0x6e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      local_8c = FLOAT_803e0cd4;
      uStack_2c = FUN_80022264(0xffffffc4,0x3c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0cd8;
      local_b8 = 100;
      local_7c = 0x11000004;
      local_7e = 0x151;
      local_68 = 0xff00;
      local_66 = 0x4000;
      local_64 = 0;
      local_74 = 0x4000;
      local_70 = 0xc800;
      local_6c = 0;
      local_bc = 0x4c0;
      local_78 = 0x20;
      break;
    case 0x4c0:
      local_8c = FLOAT_803e0cdc;
      local_b8 = 0x4b;
      uStack_24 = 0x8000004b;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e0ce0 * (float)(4503601774854219.0 - DOUBLE_803e0d20);
      local_7c = 0xa100200;
      local_7e = 0x56;
      break;
    case 0x4c1:
      uStack_24 = FUN_80022264(0xfffffffb,5);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0xffffff88,0x78);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      uVar2 = FUN_80022264(0xffffffff,1);
      uStack_44 = uVar2 * 0xc ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0d20);
      uStack_4c = FUN_80022264(0xffffffba,0x46);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0c88;
      local_b8 = 200;
      local_7c = 0xa100100;
      local_7e = 0xc10;
      local_68 = 0xff00;
      local_66 = 0xff00;
      local_64 = 0;
      local_74 = 0xff00;
      local_70 = 0;
      local_6c = 0x8000;
      local_78 = 0x20;
      break;
    case 0x4c2:
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0ce4;
      local_b8 = 0x46;
      local_7c = 0xa100200;
      local_78 = 0x1000800;
      local_7e = 0x5f;
      local_60 = 0x40;
      break;
    case 0x4c3:
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xfffffe70,400);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      uStack_3c = FUN_80022264(0xfffffe70,400);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0ce8;
      local_b8 = 600;
      local_60 = 0x7f;
      local_7c = 0xa100100;
      local_7e = 0x62;
      break;
    case 0x4c4:
      local_84 = FLOAT_803e0ce8;
      local_b8 = FUN_80022264(100,300);
      local_60 = 0xb4;
      local_7c = 0x80180208;
      local_7e = 0x62;
      break;
    case 0x4c5:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d064 = FLOAT_803e0c80;
        DAT_8039d068 = FLOAT_803e0c80;
        DAT_8039d06c = FLOAT_803e0c80;
        DAT_8039d060 = FLOAT_803e0cec;
        DAT_8039d058 = 0;
        DAT_8039d05a = 0;
        DAT_8039d05c = 0;
      }
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0c8c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(10,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0cf0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_cc = FLOAT_803e0c80;
      local_c8 = FLOAT_803e0c80;
      local_c4 = FLOAT_803e0c80;
      local_d0 = FLOAT_803e0cec;
      local_d4 = puVar1[2];
      local_d6 = puVar1[1];
      local_d8 = *puVar1;
      FUN_80021b8c(&local_d8,&local_9c);
      local_7c = 0x3000000;
      local_78 = 0x200000;
      local_84 = FLOAT_803e0c8c;
      local_60 = 0xff;
      local_b8 = 0x32;
      local_7e = 0x151;
      break;
    case 0x4c6:
      local_60 = 0x40;
      local_84 = FLOAT_803e0cbc;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = FLOAT_803e0c80;
      local_a4 = FLOAT_803e0c80;
      local_a0 = FLOAT_803e0c80;
      local_ac = FLOAT_803e0cec;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c7:
      local_60 = 0x40;
      local_84 = FLOAT_803e0cf4;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = FLOAT_803e0c80;
      local_a4 = FLOAT_803e0c80;
      local_a0 = FLOAT_803e0c80;
      local_ac = FLOAT_803e0cec;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c8:
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0cf8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0cf8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0cf8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0cfc;
      local_b8 = FUN_80022264(0x4b,100);
      local_60 = 0x7f;
      local_7c = 0x1080200;
      local_7e = 0x151;
      break;
    case 0x4c9:
      local_b8 = FUN_80022264(0x3c,100);
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0cbc * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0d00 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0cbc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0c90;
      local_7c = 0x3000000;
      local_78 = 0x600020;
      local_7e = 0x20d;
      local_60 = 0xff;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_66 = 0x4000;
      local_64 = 0;
      break;
    case 0x4ca:
      uStack_24 = FUN_80022264(0xffffff38,200);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0cc8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(0xffffff38,200);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0cc8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xf,0x2d);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(DOUBLE_803e0d08 *
                        (double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20));
      uStack_3c = FUN_80022264(6,0xc);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0d10 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0d20);
      local_b8 = FUN_80022264(0x46,0x82);
      local_7c = 0x1580000;
      local_78 = 0x400000;
      local_7e = 0x23b;
      local_60 = 0xff;
      break;
    case 0x4cb:
      uStack_24 = FUN_80022264(8,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = FLOAT_803e0ce8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0d14 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_b8 = FUN_80022264(0x3c,0x78);
      local_7c = 0x80080000;
      local_78 = 0x4440820;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0;
      local_68 = 0xffff;
      local_66 = 0;
      local_64 = 0;
      local_7e = 0xc0b;
      local_60 = 0x40;
      break;
    case 0x4cc:
      local_b8 = FUN_80022264(0x3c,100);
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e0cbc * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0d00 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0cbc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0d20);
      local_84 = FLOAT_803e0c90;
      local_7c = 0x3000000;
      local_78 = 0x600020;
      local_7e = 0x20d;
      local_60 = 0xff;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0xffff;
      local_68 = 0x4000;
      local_66 = 0xffff;
      local_64 = 0;
      break;
    case 0x4cd:
      uStack_24 = FUN_80022264(8,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = FLOAT_803e0ce8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d20);
      uStack_2c = FUN_80022264(6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0d14 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d20);
      local_b8 = FUN_80022264(0x3c,0x78);
      local_7c = 0x80080000;
      local_78 = 0x4440820;
      local_74 = 0xffff;
      local_70 = 0xffff;
      local_6c = 0;
      local_68 = 0;
      local_66 = 0xffff;
      local_64 = 0;
      local_7e = 0xc0b;
      local_60 = 0x40;
    }
    local_7c = local_7c | param_4;
    if (((local_7c & 1) != 0) && ((local_7c & 2) != 0)) {
      local_7c = local_7c ^ 2;
    }
    if ((local_7c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c0 != (ushort *)0x0) {
          local_90 = local_90 + *(float *)(local_c0 + 0xc);
          local_8c = local_8c + *(float *)(local_c0 + 0xe);
          local_88 = local_88 + *(float *)(local_c0 + 0x10);
        }
      }
      else {
        local_90 = local_90 + local_a8;
        local_8c = local_8c + local_a4;
        local_88 = local_88 + local_a0;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0xffffffff,(int)uVar3,0);
  }
LAB_800c826c:
  FUN_80286888();
  return;
}

