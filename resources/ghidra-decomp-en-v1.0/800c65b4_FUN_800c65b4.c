// Function: FUN_800c65b4
// Entry: 800c65b4
// Size: 6724 bytes

void FUN_800c65b4(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  undefined2 *puVar1;
  undefined4 uVar2;
  int iVar3;
  undefined8 uVar4;
  undefined2 local_d8;
  undefined2 local_d6;
  undefined2 local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  undefined2 *local_c0;
  undefined4 local_bc;
  uint local_b8;
  undefined2 local_b4;
  undefined2 local_b2;
  undefined2 local_b0;
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
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  byte local_60;
  undefined local_5f;
  undefined local_5e;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  
  uVar4 = FUN_802860d8();
  puVar1 = (undefined2 *)((ulonglong)uVar4 >> 0x20);
  if (puVar1 == (undefined2 *)0x0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800c7fe0;
      }
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
    local_62 = (undefined)uVar4;
    local_90 = FLOAT_803e0000;
    local_8c = FLOAT_803e0000;
    local_88 = FLOAT_803e0000;
    local_9c = FLOAT_803e0000;
    local_98 = FLOAT_803e0000;
    local_94 = FLOAT_803e0000;
    local_84 = FLOAT_803e0000;
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
    switch((int)uVar4) {
    case 0x4b0:
      if (param_6 == (float *)0x0) {
        uVar2 = 0;
        goto LAB_800c7fe0;
      }
      uStack84 = (int)(uint)*(ushort *)param_6 >> 1 & 0xff;
      local_60 = (byte)uStack84;
      local_58 = 0x43300000;
      local_84 = FLOAT_803e0004 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0098);
      local_b8 = 1;
      local_7c = 0x80000;
      local_78 = 0x800;
      local_7e = 0xc7e;
      break;
    case 0x4b1:
      uStack84 = FUN_800221a0(0xffffff9c,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0008 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e00a0);
      uStack76 = FUN_800221a0(0xffffffe7,0x96);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e00a0);
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e0008 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      local_b8 = 100;
      local_84 = FLOAT_803e0010;
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
      local_84 = FLOAT_803e0014;
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
      local_84 = FLOAT_803e0018;
      local_7c = 0x100200;
      local_78 = 0x4000800;
      local_7e = 0x73;
      break;
    case 0x4b4:
      uStack68 = FUN_800221a0(0xffffffff,1);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      uStack76 = FUN_800221a0(0xfffffff9,7);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e00a0);
      uStack84 = FUN_800221a0(0xffffffff,1);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0xfffffff9,7);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xfffffff9,7);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack36 = FUN_800221a0(0x32,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e001c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      local_60 = FUN_800221a0(0x5c,0xc0);
      local_b8 = FUN_800221a0(0x32,0x50);
      local_7c = 0x1180000;
      local_78 = 0x4400820;
      local_7e = 0x30;
      local_68 = 0;
      local_66 = FUN_800221a0(0,0xffff);
      local_64 = FUN_800221a0(0,0xffff);
      local_74 = 0;
      local_70 = 0xff00;
      local_6c = FUN_800221a0(0,0xffff);
      break;
    case 0x4b5:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_84 = FLOAT_803e0020;
      local_b8 = 0x5f;
      local_7c = 0x1180200;
      local_78 = 0x4000820;
      local_7e = 0x62;
      local_68 = 0;
      local_66 = FUN_800221a0(0x8000,0xffff);
      local_64 = 0;
      local_74 = FUN_800221a0(0,0x8000);
      local_70 = FUN_800221a0(0,0xffff);
      local_6c = 0;
      break;
    case 0x4b6:
      if (param_6 != (float *)0x0) {
        local_9c = *param_6;
        local_98 = param_6[1];
        local_94 = param_6[2];
      }
      local_60 = 0x40;
      local_84 = FLOAT_803e0024;
      local_b8 = 0x32;
      local_7c = 0x180110;
      local_78 = 0x4000800;
      local_7e = 0x62;
      break;
    case 0x4b7:
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      local_8c = FLOAT_803e0028;
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e000c;
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
      local_84 = FLOAT_803e002c;
      local_7c = 0x80200;
      local_78 = 0x4000800;
      iVar3 = FUN_800221a0(0,2);
      if (iVar3 == 0) {
        local_7e = 0xc0e;
      }
      else {
        local_7e = FUN_800221a0(0x156,0x157);
      }
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800c7fe0;
    case 0x4ba:
      uStack36 = FUN_800221a0(0xfffffff9,7);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xfffffff9,7);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xfffffff9,7);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0xffffffce,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0024 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      uStack68 = FUN_800221a0(0xffffffce,0x32);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e0024 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      uStack76 = FUN_800221a0(0xffffffce,0x32);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0024 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e000c;
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
      local_84 = FLOAT_803e0030;
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
      if (param_6 == (float *)0x0) {
        uVar2 = 0;
        goto LAB_800c7fe0;
      }
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      uStack44 = (uint)local_60;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0034 *
                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0098) *
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      uStack60 = (uint)local_60;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0034 *
                 (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e0098) *
                 (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      uStack76 = (uint)local_60;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e0034 *
                 (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e0098) *
                 (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      uStack84 = (uint)*param_6 & 0xff;
      local_60 = (byte)uStack84;
      local_58 = 0x43300000;
      local_84 = FLOAT_803e0038 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0098) +
                 FLOAT_803e0038;
      local_b8 = FUN_800221a0(0xf,0x1e);
      local_7c = 0xc1080100;
      local_78 = 0x800;
      local_7e = 0xdb;
      break;
    case 0x4bd:
      uStack36 = FUN_800221a0(0xfffffffb,5);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0,0xf);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      local_98 = FLOAT_803e003c;
      uStack60 = FUN_800221a0(5,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0040 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      local_b8 = FUN_800221a0(0x3c,0x5a);
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
      uStack36 = FUN_800221a0(0xfffffe3e,0x1c2);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      local_8c = FLOAT_803e0044;
      uStack44 = FUN_800221a0(0xfffffe3e,0x1c2);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e0048 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      uStack68 = FUN_800221a0(0xffffffec,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      uStack76 = FUN_800221a0(0,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = FLOAT_803e0050 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e00a0) +
                 FLOAT_803e004c;
      local_b8 = FUN_800221a0(0xbe,0xfa);
      local_7c = 0x81488000;
      local_7e = FUN_800221a0(0,2);
      local_7e = local_7e + 0x208;
      local_68 = 0x2000;
      local_66 = 0x8000;
      local_64 = 0xc000;
      local_74 = 0xc000;
      local_70 = 0xff00;
      local_6c = 0xff00;
      local_78 = 0x20;
      break;
    case 0x4bf:
      uStack36 = FUN_800221a0(0xffffff92,0x6e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      local_8c = FLOAT_803e0054;
      uStack44 = FUN_800221a0(0xffffffc4,0x3c);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0058;
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
      local_8c = FLOAT_803e005c;
      local_b8 = 0x4b;
      uStack36 = 0x8000004b;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e0060 * (float)(4503601774854219.0 - DOUBLE_803e00a0);
      local_7c = 0xa100200;
      local_7e = 0x56;
      break;
    case 0x4c1:
      uStack36 = FUN_800221a0(0xfffffffb,5);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xfffffffb,5);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0xffffff88,0x78);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      iVar3 = FUN_800221a0(0xffffffff,1);
      uStack68 = iVar3 * 0xc ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e00a0);
      uStack76 = FUN_800221a0(0xffffffba,0x46);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0008;
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
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0064;
      local_b8 = 0x46;
      local_7c = 0xa100200;
      local_78 = 0x1000800;
      local_7e = 0x5f;
      local_60 = 0x40;
      break;
    case 0x4c3:
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xfffffe70,400);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      uStack60 = FUN_800221a0(0xfffffe70,400);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0068;
      local_b8 = 600;
      local_60 = 0x7f;
      local_7c = 0xa100100;
      local_7e = 0x62;
      break;
    case 0x4c4:
      local_84 = FLOAT_803e0068;
      local_b8 = FUN_800221a0(100,300);
      local_60 = 0xb4;
      local_7c = 0x80180208;
      local_7e = 0x62;
      break;
    case 0x4c5:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c404 = FLOAT_803e0000;
        DAT_8039c408 = FLOAT_803e0000;
        DAT_8039c40c = FLOAT_803e0000;
        DAT_8039c400 = FLOAT_803e006c;
        DAT_8039c3f8 = 0;
        DAT_8039c3fa = 0;
        DAT_8039c3fc = 0;
      }
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e000c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(10,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0070 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      local_cc = FLOAT_803e0000;
      local_c8 = FLOAT_803e0000;
      local_c4 = FLOAT_803e0000;
      local_d0 = FLOAT_803e006c;
      local_d4 = puVar1[2];
      local_d6 = puVar1[1];
      local_d8 = *puVar1;
      FUN_80021ac8(&local_d8,&local_9c);
      local_7c = 0x3000000;
      local_78 = 0x200000;
      local_84 = FLOAT_803e000c;
      local_60 = 0xff;
      local_b8 = 0x32;
      local_7e = 0x151;
      break;
    case 0x4c6:
      local_60 = 0x40;
      local_84 = FLOAT_803e003c;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = FLOAT_803e0000;
      local_a4 = FLOAT_803e0000;
      local_a0 = FLOAT_803e0000;
      local_ac = FLOAT_803e006c;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c7:
      local_60 = 0x40;
      local_84 = FLOAT_803e0074;
      local_b8 = 1;
      local_7c = 0x6000000;
      local_7e = 0x45b;
      local_a8 = FLOAT_803e0000;
      local_a4 = FLOAT_803e0000;
      local_a0 = FLOAT_803e0000;
      local_ac = FLOAT_803e006c;
      local_b0 = puVar1[2];
      local_b2 = puVar1[1];
      local_b4 = *puVar1;
      break;
    case 0x4c8:
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0078 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0078 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0078 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e007c;
      local_b8 = FUN_800221a0(0x4b,100);
      local_60 = 0x7f;
      local_7c = 0x1080200;
      local_7e = 0x151;
      break;
    case 0x4c9:
      local_b8 = FUN_800221a0(0x3c,100);
      uStack36 = FUN_800221a0(0xffffffce,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e003c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0080 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e003c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0010;
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
      uStack36 = FUN_800221a0(0xffffff38,200);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0048 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(0xffffff38,200);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0048 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xf,0x2d);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)(DOUBLE_803e0088 *
                        (double)(float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0));
      uStack60 = FUN_800221a0(6,0xc);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0090 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e00a0);
      local_b8 = FUN_800221a0(0x46,0x82);
      local_7c = 0x1580000;
      local_78 = 0x400000;
      local_7e = 0x23b;
      local_60 = 0xff;
      break;
    case 0x4cb:
      uStack36 = FUN_800221a0(8,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = FLOAT_803e0068 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0094 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      local_b8 = FUN_800221a0(0x3c,0x78);
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
      local_b8 = FUN_800221a0(0x3c,100);
      uStack36 = FUN_800221a0(0xffffffce,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_9c = FLOAT_803e003c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = local_b8 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0080 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e003c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e00a0);
      local_84 = FLOAT_803e0010;
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
      uStack36 = FUN_800221a0(8,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_98 = FLOAT_803e0068 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e00a0);
      uStack44 = FUN_800221a0(6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0094 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e00a0);
      local_b8 = FUN_800221a0(0x3c,0x78);
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
        if (local_c0 != (undefined2 *)0x0) {
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
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_c0,0xffffffff,(int)uVar4,0);
  }
LAB_800c7fe0:
  FUN_80286124(uVar2);
  return;
}

