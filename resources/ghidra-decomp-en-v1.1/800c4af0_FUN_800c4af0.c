// Function: FUN_800c4af0
// Entry: 800c4af0
// Size: 3692 bytes

void FUN_800c4af0(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  int local_b8 [3];
  ushort local_ac;
  ushort local_aa;
  ushort local_a8;
  undefined4 local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  undefined2 local_78;
  ushort local_76;
  uint local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined2 local_60;
  undefined2 local_5e;
  undefined2 local_5c;
  undefined local_5a;
  undefined local_58;
  undefined local_57;
  undefined local_56;
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
  undefined4 local_20;
  uint uStack_1c;
  
  uVar3 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800c5944;
      local_a0 = *(float *)(param_3 + 6);
      local_9c = *(float *)(param_3 + 8);
      local_98 = *(float *)(param_3 + 10);
      local_a4 = *(undefined4 *)(param_3 + 4);
      local_a8 = param_3[2];
      local_aa = param_3[1];
      local_ac = *param_3;
      local_56 = param_5;
    }
    local_74 = 0;
    local_70 = 0;
    local_5a = (undefined)uVar3;
    local_88 = FLOAT_803e0bb8;
    local_84 = FLOAT_803e0bb8;
    local_80 = FLOAT_803e0bb8;
    local_94 = FLOAT_803e0bb8;
    local_90 = FLOAT_803e0bb8;
    local_8c = FLOAT_803e0bb8;
    local_7c = FLOAT_803e0bb8;
    local_b8[2] = 0;
    local_b8[1] = 0xffffffff;
    local_58 = 0xff;
    local_57 = 0;
    local_76 = 0;
    local_60 = 0xffff;
    local_5e = 0xffff;
    local_5c = 0xffff;
    local_6c = 0xffff;
    local_68 = 0xffff;
    local_64 = 0xffff;
    local_78 = 0;
    local_b8[0] = iVar1;
    switch((int)uVar3) {
    case 300:
      local_7c = FLOAT_803e0bbc;
      local_b8[2] = 10;
      local_58 = 0xff;
      local_74 = 0x40200;
      local_76 = 0xdb;
      break;
    case 0x12d:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      local_7c = FLOAT_803e0bc4;
      local_b8[2] = FUN_80022264(0,0x1e);
      local_b8[2] = local_b8[2] + 0x46;
      if (*(float *)(param_3 + 4) <= FLOAT_803e0bb8) {
        local_58 = 0x41;
      }
      else {
        local_58 = 0x50;
      }
      local_74 = 0x80110;
      if (*(float *)(param_3 + 4) <= FLOAT_803e0bb8) {
        local_76 = 0xdb;
      }
      else {
        local_76 = 0x7b;
      }
      break;
    case 0x12e:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e0bc8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_84 = FLOAT_803e0bb8;
      local_80 = FLOAT_803e0bcc;
      uStack_44 = FUN_80022264(1,3);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803e0bd0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20);
      local_94 = FLOAT_803e0bc8 * *(float *)(param_3 + 6);
      local_8c = FLOAT_803e0bc8 * -*(float *)(param_3 + 10);
      uStack_3c = FUN_80022264(1,3);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = FLOAT_803e0bbc * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      local_b8[2] = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x12f:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bc8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      local_84 = FLOAT_803e0bb8;
      local_80 = FLOAT_803e0bcc;
      uStack_44 = FUN_80022264(1,3);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803e0bd0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20);
      local_94 = FLOAT_803e0bd4 * *(float *)(param_3 + 6);
      local_8c = FLOAT_803e0bd4 * -*(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(1,3);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803e0bd8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_b8[2] = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x130:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bc8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      local_84 = FLOAT_803e0bb8;
      local_80 = FLOAT_803e0bcc;
      uStack_44 = FUN_80022264(1,3);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803e0bd0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20);
      local_94 = FLOAT_803e0bdc * *(float *)(param_3 + 6);
      local_8c = FLOAT_803e0bdc * -*(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(1,3);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803e0be0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_b8[2] = 0x19;
      local_58 = 0x55;
      local_74 = 0x80118;
      local_76 = 0x5f;
      break;
    case 0x131:
      uStack_3c = FUN_80022264(0xfffffff4,0xc);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bd0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      uStack_44 = FUN_80022264(0xfffffff4,0xc);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0bd0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20)
                 + FLOAT_803e0be4;
      local_80 = FLOAT_803e0bcc;
      uStack_4c = FUN_80022264(5,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e0be8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_7c = FLOAT_803e0bec;
      local_b8[2] = 100;
      local_58 = 0xff;
      local_74 = 0x100;
      local_76 = 0x33;
      break;
    case 0x132:
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_7c = FLOAT_803e0bf4;
      local_b8[2] = FUN_80022264(0x78,0x96);
      local_57 = 0x1e;
      local_58 = 0xff;
      local_74 = 0x11;
      local_76 = 0x5f;
      break;
    case 0x133:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      local_7c = FLOAT_803e0bf4;
      local_b8[2] = 5;
      local_58 = 0x80;
      local_74 = 0x80210;
      local_76 = 0x26d;
      break;
    case 0x134:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_3c = FUN_80022264(0xffffff38,200);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bf8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20)
                 + *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      uStack_44 = FUN_80022264(0xffffff38,200);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803e0bf8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20)
                 + *(float *)(param_3 + 10);
      uStack_4c = FUN_80022264(5,0xc);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803e0bfc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      local_b8[2] = 0xc;
      uVar2 = FUN_80022264(0x96,0xfa);
      local_58 = (undefined)uVar2;
      local_74 = local_74 | 0x80210;
      local_76 = 0xe0;
      break;
    case 0x135:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c20);
      uStack_44 = FUN_80022264(0xffffffe2,0);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c20);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = FLOAT_803e0bf0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0c20);
      uStack_34 = FUN_80022264(0xfffffff1,0xf);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0bf4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c20);
      uStack_2c = FUN_80022264(0xf,0x23);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e0c00 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c20);
      uStack_24 = FUN_80022264(0xfffffff1,0xf);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0bf4 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c20);
      uStack_1c = FUN_80022264(100,0x96);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803e0c04 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c20);
      local_b8[2] = FUN_80022264(0x32,0x50);
      uVar2 = FUN_80022264(10,0x1e);
      local_57 = (undefined)uVar2;
      local_74 = 0x218;
      local_76 = param_3[2];
      break;
    case 0x136:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      uStack_1c = FUN_80022264(-(int)(short)param_3[1],(int)(short)param_3[1]);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c20) / FLOAT_803e0c08;
      uStack_24 = FUN_80022264(-(int)(short)param_3[1],(int)(short)param_3[1]);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c20) / FLOAT_803e0c08;
      uStack_2c = FUN_80022264(-(int)(short)param_3[1],(int)(short)param_3[1]);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c20) / FLOAT_803e0c08;
      local_7c = FLOAT_803e0c0c;
      local_b8[2] = FUN_80022264(0x14,0x1e);
      local_74 = 0x100200;
      local_76 = param_3[2];
      break;
    case 0x137:
      if (param_3 == (ushort *)0x0) {
        DAT_8039d034 = FLOAT_803e0bb8;
        DAT_8039d038 = FLOAT_803e0bb8;
        DAT_8039d03c = FLOAT_803e0bb8;
        DAT_8039d030 = FLOAT_803e0bc0;
        DAT_8039d028 = 0;
        DAT_8039d02a = 0;
        DAT_8039d02c = 0;
        param_3 = &DAT_8039d028;
      }
      if (param_3 == (ushort *)0x0) goto LAB_800c5944;
      uStack_1c = FUN_80022264(0,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_94 = FLOAT_803e0c14 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c20)
                 + FLOAT_803e0c10;
      uStack_24 = FUN_80022264(0,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0c18 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c20)
                 + FLOAT_803e0bf4;
      uStack_2c = FUN_80022264(0,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0c18 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c20)
                 + FLOAT_803e0bf4;
      FUN_80021b8c(param_3,&local_94);
      uStack_34 = FUN_80022264(0x14,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803e0c1c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c20);
      local_58 = 0xff;
      local_b8[2] = 0xf0;
      local_57 = 0x10;
      local_b8[1] = 0x138;
      local_74 = 0x480200;
      local_70 = 0x100000;
      local_76 = 0x167;
      break;
    case 0x138:
      uStack_1c = FUN_80022264(0x14,0x1e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803e0bfc * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c20);
      local_58 = 0x37;
      local_b8[2] = 4;
      local_57 = 0x10;
      local_74 = 0x80201;
      local_70 = 2;
      local_76 = 0x167;
      break;
    default:
      goto LAB_800c5944;
    }
    local_74 = local_74 | param_4;
    if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
      local_74 = local_74 ^ 2;
    }
    if ((local_74 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b8[0] != 0) {
          local_88 = local_88 + *(float *)(local_b8[0] + 0x18);
          local_84 = local_84 + *(float *)(local_b8[0] + 0x1c);
          local_80 = local_80 + *(float *)(local_b8[0] + 0x20);
        }
      }
      else {
        local_88 = local_88 + local_a0;
        local_84 = local_84 + local_9c;
        local_80 = local_80 + local_98;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(local_b8,0xffffffff,(int)uVar3,0);
  }
LAB_800c5944:
  FUN_8028688c();
  return;
}

