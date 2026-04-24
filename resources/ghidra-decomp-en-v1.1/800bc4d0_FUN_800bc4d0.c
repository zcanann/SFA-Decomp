// Function: FUN_800bc4d0
// Entry: 800bc4d0
// Size: 4292 bytes

void FUN_800bc4d0(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar4;
  ushort local_d8 [4];
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  int local_c0 [3];
  ushort local_b4;
  ushort local_b2;
  ushort local_b0;
  undefined4 local_ac;
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
  undefined2 local_80;
  undefined2 local_7e;
  uint local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined2 local_68;
  undefined2 local_66;
  undefined2 local_64;
  undefined local_62;
  undefined local_60;
  undefined local_5f;
  undefined local_5e;
  undefined8 local_58;
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
  undefined8 local_28;
  
  uVar4 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  FLOAT_803dc440 = FLOAT_803dc440 + FLOAT_803e0860;
  if (FLOAT_803e0868 < FLOAT_803dc440) {
    FLOAT_803dc440 = FLOAT_803e0864;
  }
  FLOAT_803dc444 = FLOAT_803dc444 + FLOAT_803e086c;
  if (FLOAT_803e0868 < FLOAT_803dc444) {
    FLOAT_803dc444 = FLOAT_803e0870;
  }
  if (iVar2 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      local_a8 = *(float *)(param_3 + 6);
      local_a4 = *(float *)(param_3 + 8);
      local_a0 = *(float *)(param_3 + 10);
      local_ac = *(undefined4 *)(param_3 + 4);
      local_b0 = param_3[2];
      local_b2 = param_3[1];
      local_b4 = *param_3;
      local_5e = param_5;
    }
    local_7c = 0;
    local_78 = 0;
    local_62 = (undefined)uVar4;
    local_90 = FLOAT_803e0874;
    local_8c = FLOAT_803e0874;
    local_88 = FLOAT_803e0874;
    local_9c = FLOAT_803e0874;
    local_98 = FLOAT_803e0874;
    local_94 = FLOAT_803e0874;
    local_84 = FLOAT_803e0874;
    local_c0[2] = 0;
    local_c0[1] = 0xffffffff;
    local_60 = 0xff;
    local_5f = 0;
    local_7e = 0;
    local_68 = 0xffff;
    local_66 = 0xffff;
    local_64 = 0xffff;
    local_74 = 0xffff;
    local_70 = 0xffff;
    local_6c = 0xffff;
    local_80 = 0;
    local_c0[0] = iVar2;
    switch((int)uVar4) {
    case 200:
      uVar3 = FUN_80022264(0xfffffffa,6);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_58 - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0xfffffffa,6);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0xfffffffa,6);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(4,8);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0878 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0x24;
      local_60 = 0x41;
      local_7c = 0x100111;
      local_7e = 0xc10;
      break;
    default:
      goto LAB_800bd57c;
    case 0xca:
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      uStack_3c = FUN_80022264(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e087c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e087c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0880 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = FLOAT_803e0874;
      local_c8 = FLOAT_803e0874;
      local_c4 = FLOAT_803e0874;
      local_d0 = FLOAT_803e0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = *param_3;
      FUN_80021b8c(local_d8,&local_9c);
      uVar3 = FUN_80022264(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e0884 * (float)(local_58 - DOUBLE_803e08f0);
      local_c0[2] = 0x46;
      local_60 = 100;
      local_5f = 0;
      local_7c = 0x180108;
      local_78 = 0x5000000;
      uVar1 = param_3[2];
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcb:
      if (param_3 == (ushort *)0x0) goto LAB_800bd57c;
      uStack_3c = FUN_80022264(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0888 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(10,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e088c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x14,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e0888 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      local_cc = FLOAT_803e0874;
      local_c8 = FLOAT_803e0874;
      local_c4 = FLOAT_803e0874;
      local_d0 = FLOAT_803e0868;
      local_d8[2] = 0;
      local_d8[1] = 0;
      local_d8[0] = *param_3;
      FUN_80021b8c(local_d8,&local_9c);
      uVar3 = FUN_80022264(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e0890 * (float)(local_58 - DOUBLE_803e08f0);
      local_c0[2] = 0x46;
      local_60 = 0xff;
      local_5f = 0;
      local_7c = 0x1080100;
      local_78 = 0x5000000;
      uVar1 = param_3[2];
      if (uVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (uVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (uVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcc:
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(1,2);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0894 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0xfffffff6,10);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_9c = FLOAT_803e0898 * (float)(local_58 - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0898 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(4,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e089c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0xff;
      local_7c = 0x80108;
      local_7e = 0x5c;
      break;
    case 0xcd:
      uStack_2c = FUN_80022264(0,0xfa);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e08a0 + local_90 / FLOAT_803e08a0 +
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_88 = FLOAT_803e08a4 * local_90;
      uStack_3c = FUN_80022264(0x28,0x50);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e08a8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xce:
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e08ac + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff8,8);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e08b0 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e08b4 + (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e08b8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0x28,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = FLOAT_803e086c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_c0[2] = (int)(FLOAT_803e08bc + (float)(local_58 - DOUBLE_803e08f0));
      local_28 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xcf:
      uVar3 = FUN_80022264(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08a0 + local_90 / FLOAT_803e08a0 +
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      local_88 = -local_90;
      uStack_34 = FUN_80022264(0x28,0x50);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e08a8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      local_c0[2] = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xd0:
      uVar3 = FUN_80022264(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = FLOAT_803e08c0 + (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffff8,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08b0 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e08c4 + (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08b8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e086c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(FLOAT_803e08bc +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd1:
      uVar3 = FUN_80022264(0x46,0x50);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_84 = FLOAT_803e086c * (float)(local_28 - DOUBLE_803e08f0);
      uVar3 = FUN_80022264(0,0xf);
      local_c0[2] = uVar3 + 0x14;
      local_5f = 0;
      local_60 = 0xff;
      local_7c = 0x180210;
      local_7e = 0x159;
      break;
    case 0xd2:
      local_84 = FLOAT_803e087c;
      local_c0[2] = 0x50;
      local_7c = 0x400000;
      local_7e = 0x159;
      break;
    case 0xd3:
      uVar3 = FUN_80022264(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xfffffffb,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08c8 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xfffffffb,5);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803e0864 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08cc * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      local_c0[2] = 0xa0;
      local_60 = 0x7d;
      local_7c = 0x180108;
      local_7e = 0x5c;
      break;
    case 0xd4:
      uVar3 = FUN_80022264(0xfffffff6,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0,0x1c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08d0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08d4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      uStack_4c = FUN_80022264(0,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_c0[2] = (int)(FLOAT_803e08d8 +
                         (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e08f0));
      local_58 = (double)(longlong)local_c0[2];
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd5:
      local_84 = FLOAT_803e08dc;
      local_c0[1] = 0xd6;
      local_c0[2] = 100;
      local_60 = 0xff;
      local_7c = 0x80000;
      local_7e = 0x159;
      break;
    case 0xd6:
      local_84 = FLOAT_803e08dc;
      local_c0[2] = 0x28;
      local_60 = 0xff;
      local_7c = 0x80100;
      local_7e = 0x159;
      break;
    case 0xd7:
      uVar3 = FUN_80022264(0xffffff74,0x8c);
      local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_90 = FLOAT_803e08e0 * (float)(local_28 - DOUBLE_803e08f0);
      uStack_2c = FUN_80022264(0xffffffce,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e08e0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e08f0);
      uStack_34 = FUN_80022264(0xffffff74,0x8c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e08e0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e08f0);
      uStack_3c = FUN_80022264(0xf,0x23);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e08e4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e08f0);
      uStack_44 = FUN_80022264(1,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e08e8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e08f0);
      local_c0[2] = 0x8c;
      local_60 = 0xff;
      local_7c = 0x80180100;
      local_7e = 0x5f;
    }
    local_7c = local_7c | param_4;
    if (((local_7c & 1) != 0) && ((param_4 & 2) != 0)) {
      local_7c = local_7c ^ 2;
    }
    if ((local_7c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c0[0] != 0) {
          local_90 = local_90 + *(float *)(local_c0[0] + 0x18);
          local_8c = local_8c + *(float *)(local_c0[0] + 0x1c);
          local_88 = local_88 + *(float *)(local_c0[0] + 0x20);
        }
      }
      else {
        local_90 = local_90 + local_a8;
        local_8c = local_8c + local_a4;
        local_88 = local_88 + local_a0;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(local_c0,0xffffffff,(int)uVar4,0);
  }
LAB_800bd57c:
  FUN_8028688c();
  return;
}

