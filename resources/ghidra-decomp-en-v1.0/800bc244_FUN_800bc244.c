// Function: FUN_800bc244
// Entry: 800bc244
// Size: 4292 bytes

void FUN_800bc244(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  undefined8 uVar5;
  undefined2 local_d8;
  undefined2 local_d6;
  undefined2 local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  int local_c0;
  undefined4 local_bc;
  int local_b8;
  undefined2 local_b4;
  undefined2 local_b2;
  undefined2 local_b0;
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
  double local_58;
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
  double local_28;
  
  uVar5 = FUN_802860dc();
  iVar2 = (int)((ulonglong)uVar5 >> 0x20);
  FLOAT_803db7e0 = FLOAT_803db7e0 + FLOAT_803dfbe0;
  if (FLOAT_803dfbe8 < FLOAT_803db7e0) {
    FLOAT_803db7e0 = FLOAT_803dfbe4;
  }
  FLOAT_803db7e4 = FLOAT_803db7e4 + FLOAT_803dfbec;
  if (FLOAT_803dfbe8 < FLOAT_803db7e4) {
    FLOAT_803db7e4 = FLOAT_803dfbf0;
  }
  if (iVar2 == 0) {
    uVar3 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar3 = 0xffffffff;
        goto LAB_800bd2f0;
      }
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
    local_62 = (undefined)uVar5;
    local_90 = FLOAT_803dfbf4;
    local_8c = FLOAT_803dfbf4;
    local_88 = FLOAT_803dfbf4;
    local_9c = FLOAT_803dfbf4;
    local_98 = FLOAT_803dfbf4;
    local_94 = FLOAT_803dfbf4;
    local_84 = FLOAT_803dfbf4;
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
    local_80 = 0;
    local_c0 = iVar2;
    switch((int)uVar5) {
    case 200:
      uVar4 = FUN_800221a0(0xfffffffa,6);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = (float)(local_58 - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0xfffffffa,6);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(0xfffffffa,6);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(4,8);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfbf8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      local_b8 = 0x24;
      local_60 = 0x41;
      local_7c = 0x100111;
      local_7e = 0xc10;
      break;
    default:
      uVar3 = 0xffffffff;
      goto LAB_800bd2f0;
    case 0xca:
      if (param_3 == (undefined2 *)0x0) {
        uVar3 = 0;
        goto LAB_800bd2f0;
      }
      uStack60 = FUN_800221a0(0xffffffec,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfbfc * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(10,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803dfbfc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0x14,0x1e);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803dfc00 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70);
      local_cc = FLOAT_803dfbf4;
      local_c8 = FLOAT_803dfbf4;
      local_c4 = FLOAT_803dfbf4;
      local_d0 = FLOAT_803dfbe8;
      local_d4 = 0;
      local_d6 = 0;
      local_d8 = *param_3;
      FUN_80021ac8(&local_d8,&local_9c);
      uVar4 = FUN_800221a0(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_84 = FLOAT_803dfc04 * (float)(local_58 - DOUBLE_803dfc70);
      local_b8 = 0x46;
      local_60 = 100;
      local_5f = 0;
      local_7c = 0x180108;
      local_78 = 0x5000000;
      sVar1 = param_3[2];
      if (sVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (sVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (sVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcb:
      if (param_3 == (undefined2 *)0x0) {
        uVar3 = 0;
        goto LAB_800bd2f0;
      }
      uStack60 = FUN_800221a0(0xffffffec,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfc08 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(10,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803dfc0c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0x14,0x1e);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803dfc08 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70);
      local_cc = FLOAT_803dfbf4;
      local_c8 = FLOAT_803dfbf4;
      local_c4 = FLOAT_803dfbf4;
      local_d0 = FLOAT_803dfbe8;
      local_d4 = 0;
      local_d6 = 0;
      local_d8 = *param_3;
      FUN_80021ac8(&local_d8,&local_9c);
      uVar4 = FUN_800221a0(4,8);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_84 = FLOAT_803dfc10 * (float)(local_58 - DOUBLE_803dfc70);
      local_b8 = 0x46;
      local_60 = 0xff;
      local_5f = 0;
      local_7c = 0x1080100;
      local_78 = 0x5000000;
      sVar1 = param_3[2];
      if (sVar1 == 0) {
        local_7e = 0x2b;
      }
      else if (sVar1 == 1) {
        local_7e = 0x1a1;
      }
      else if (sVar1 == 2) {
        local_7e = 0xc10;
        local_78 = 0x5000800;
      }
      else {
        local_7e = 0x2b;
      }
      break;
    case 0xcc:
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(1,2);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfc14 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70);
      uVar4 = FUN_800221a0(0xfffffff6,10);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_9c = FLOAT_803dfc18 * (float)(local_58 - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dfc18 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(4,8);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfc1c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      local_b8 = 0xfa;
      local_60 = 0xff;
      local_7c = 0x80108;
      local_7e = 0x5c;
      break;
    case 0xcd:
      uStack44 = FUN_800221a0(0,0xfa);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dfc20 + local_90 / FLOAT_803dfc20 +
                 (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      local_88 = FLOAT_803dfc24 * local_90;
      uStack60 = FUN_800221a0(0x28,0x50);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfc28 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      local_b8 = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xce:
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803dfc2c + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xfffffff8,8);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dfc30 + (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dfc34 + (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(0,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803dfc38 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0x28,0x50);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_84 = FLOAT_803dfbec * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70);
      uVar4 = FUN_800221a0(0,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_b8 = (int)(FLOAT_803dfc3c + (float)(local_58 - DOUBLE_803dfc70));
      local_28 = (double)(longlong)local_b8;
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xcf:
      uVar4 = FUN_800221a0(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(0xfffffffb,5);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfc20 + local_90 / FLOAT_803dfc20 +
                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      local_88 = -local_90;
      uStack52 = FUN_800221a0(0x28,0x50);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dfc28 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      local_b8 = 0xfa;
      local_60 = 0x7d;
      local_7c = 0x80080118;
      local_7e = 0x5c;
      break;
    case 0xd0:
      uVar4 = FUN_800221a0(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = FLOAT_803dfc40 + (float)(local_28 - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(0xfffffff8,8);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfc30 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfc44 + (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(0,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803dfc38 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(0x28,0x50);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfbec * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b8 = (int)(FLOAT_803dfc3c +
                      (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70));
      local_58 = (double)(longlong)local_b8;
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd1:
      uVar4 = FUN_800221a0(0x46,0x50);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_84 = FLOAT_803dfbec * (float)(local_28 - DOUBLE_803dfc70);
      local_b8 = FUN_800221a0(0,0xf);
      local_b8 = local_b8 + 0x14;
      local_5f = 0;
      local_60 = 0xff;
      local_7c = 0x180210;
      local_7e = 0x159;
      break;
    case 0xd2:
      local_84 = FLOAT_803dfbfc;
      local_b8 = 0x50;
      local_7c = 0x400000;
      local_7e = 0x159;
      break;
    case 0xd3:
      uVar4 = FUN_800221a0(0,0xfa);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = -(float)(local_28 - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(0xfffffffb,5);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfc48 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(0xfffffffb,5);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803dfbe4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(0x28,0x50);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfc4c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      local_b8 = 0xa0;
      local_60 = 0x7d;
      local_7c = 0x180108;
      local_7e = 0x5c;
      break;
    case 0xd4:
      uVar4 = FUN_800221a0(0xfffffff6,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = (float)(local_28 - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(0,0x1c);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(0,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803dfc50 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(0x28,0x50);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfc54 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      uStack76 = FUN_800221a0(0,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_b8 = (int)(FLOAT_803dfc58 +
                      (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfc70));
      local_58 = (double)(longlong)local_b8;
      local_60 = 0x37;
      local_7c = 0x180100;
      local_7e = 0x4c;
      break;
    case 0xd5:
      local_84 = FLOAT_803dfc5c;
      local_bc = 0xd6;
      local_b8 = 100;
      local_60 = 0xff;
      local_7c = 0x80000;
      local_7e = 0x159;
      break;
    case 0xd6:
      local_84 = FLOAT_803dfc5c;
      local_b8 = 0x28;
      local_60 = 0xff;
      local_7c = 0x80100;
      local_7e = 0x159;
      break;
    case 0xd7:
      uVar4 = FUN_800221a0(0xffffff74,0x8c);
      local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_90 = FLOAT_803dfc60 * (float)(local_28 - DOUBLE_803dfc70);
      uStack44 = FUN_800221a0(0xffffffce,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfc60 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfc70);
      uStack52 = FUN_800221a0(0xffffff74,0x8c);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfc60 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfc70);
      uStack60 = FUN_800221a0(0xf,0x23);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803dfc64 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfc70);
      uStack68 = FUN_800221a0(1,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfc68 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfc70);
      local_b8 = 0x8c;
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
        if (local_c0 != 0) {
          local_90 = local_90 + *(float *)(local_c0 + 0x18);
          local_8c = local_8c + *(float *)(local_c0 + 0x1c);
          local_88 = local_88 + *(float *)(local_c0 + 0x20);
        }
      }
      else {
        local_90 = local_90 + local_a8;
        local_8c = local_8c + local_a4;
        local_88 = local_88 + local_a0;
      }
    }
    uVar3 = (**(code **)(*DAT_803dca78 + 8))(&local_c0,0xffffffff,(int)uVar5,0);
  }
LAB_800bd2f0:
  FUN_80286128(uVar3);
  return;
}

