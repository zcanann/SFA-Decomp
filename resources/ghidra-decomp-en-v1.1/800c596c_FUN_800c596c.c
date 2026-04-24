// Function: FUN_800c596c
// Entry: 800c596c
// Size: 3780 bytes

void FUN_800c596c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  ushort *puVar1;
  uint uVar2;
  undefined8 uVar3;
  ushort local_c8 [4];
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  ushort *local_b0;
  undefined4 local_ac;
  uint local_a8;
  undefined2 local_a4;
  undefined2 local_a2;
  undefined2 local_a0;
  undefined4 local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  short local_6e;
  uint local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined2 local_58;
  undefined2 local_56;
  undefined2 local_54;
  undefined local_52;
  undefined local_50;
  undefined local_4f;
  undefined local_4e;
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
  
  uVar3 = FUN_8028683c();
  puVar1 = (ushort *)((ulonglong)uVar3 >> 0x20);
  if (puVar1 != (ushort *)0x0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800c6818;
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_9c = *(undefined4 *)(param_3 + 4);
      local_a0 = param_3[2];
      local_a2 = param_3[1];
      local_a4 = *param_3;
      local_4e = param_5;
    }
    local_6c = 0;
    local_68 = 0;
    local_52 = (undefined)uVar3;
    local_80 = FLOAT_803e0c28;
    local_7c = FLOAT_803e0c28;
    local_78 = FLOAT_803e0c28;
    local_8c = FLOAT_803e0c28;
    local_88 = FLOAT_803e0c28;
    local_84 = FLOAT_803e0c28;
    local_74 = FLOAT_803e0c28;
    local_a8 = 0;
    local_ac = 0xffffffff;
    local_50 = 0xff;
    local_4f = 0;
    local_6e = 0;
    local_58 = 0xffff;
    local_56 = 0xffff;
    local_54 = 0xffff;
    local_64 = 0xffff;
    local_60 = 0xffff;
    local_5c = 0xffff;
    local_b0 = puVar1;
    switch((int)uVar3) {
    case 0x47e:
      local_74 = FLOAT_803e0c2c;
      local_a8 = FUN_80022264(0x32,0x3c);
      local_50 = 0x4b;
      local_6c = 0x180110;
      local_68 = 0x4000800;
      local_6e = 0x159;
      break;
    default:
      goto LAB_800c6818;
    case 0x483:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d04c = FLOAT_803e0c28;
        DAT_8039d050 = FLOAT_803e0c28;
        DAT_8039d054 = FLOAT_803e0c28;
        DAT_8039d048 = FLOAT_803e0c30;
        DAT_8039d040 = 0;
        DAT_8039d042 = 0;
        DAT_8039d044 = 0;
        param_3 = &DAT_8039d040;
      }
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c78);
      uStack_3c = FUN_80022264(0xfffffff6,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      uStack_2c = FUN_80022264(0x28,0x50);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      local_74 = FLOAT_803e0c38;
      local_a8 = 0x3c;
      local_6c = 0x81080200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0x3c;
      break;
    case 0x484:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d04c = FLOAT_803e0c28;
        DAT_8039d050 = FLOAT_803e0c28;
        DAT_8039d054 = FLOAT_803e0c28;
        DAT_8039d048 = FLOAT_803e0c30;
        DAT_8039d040 = 0;
        DAT_8039d042 = 0;
        DAT_8039d044 = 0;
        param_3 = &DAT_8039d040;
      }
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0c38 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      uStack_2c = FUN_80022264(0x14,0x50);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0c38 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0c38 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      local_74 = FLOAT_803e0c3c;
      local_a8 = 0x3c;
      local_68 = 0x200000;
      local_6c = 0x3000200;
      local_6e = 0x185;
      local_50 = 0x7f;
      break;
    case 0x485:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d04c = FLOAT_803e0c28;
        DAT_8039d050 = FLOAT_803e0c28;
        DAT_8039d054 = FLOAT_803e0c28;
        DAT_8039d048 = FLOAT_803e0c30;
        DAT_8039d040 = 0;
        DAT_8039d042 = 0;
        DAT_8039d044 = 0;
        param_3 = &DAT_8039d040;
      }
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      uStack_3c = FUN_80022264(0x28,0x50);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c78);
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0c34 * *(float *)(param_3 + 4) *
                 (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c78);
      local_74 = FLOAT_803e0c38;
      local_a8 = 0x3c;
      local_6c = 0x81080200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0x3c;
      break;
    case 0x486:
      local_80 = FLOAT_803e0c40;
      local_7c = FLOAT_803e0c44;
      local_78 = FLOAT_803e0c40;
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0c48 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      uStack_2c = FUN_80022264(0xffffffd8,0x140);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0c4c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0c48 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      uStack_3c = FUN_80022264(10,0xf);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_74 = FLOAT_803e0c50 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c78);
      local_a8 = FUN_80022264(0x2c,0x2f);
      local_6e = 0x156;
      local_50 = 0x7f;
      local_6c = 0xc80000;
      local_68 = 0x908;
      break;
    case 0x487:
      if (param_6 == (float *)0x0) goto LAB_800c6818;
      local_8c = *param_6;
      local_88 = param_6[1];
      local_84 = param_6[2];
      local_74 = FLOAT_803e0c54;
      local_50 = 0x40;
      local_a8 = 100;
      local_6c = 0x3000200;
      local_6e = 0x62;
      local_68 = 0x200000;
      break;
    case 0x488:
      uStack_24 = FUN_80022264(0xffffffe8,0x18);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803e0c40 + (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      local_7c = FLOAT_803e0c28;
      uStack_2c = FUN_80022264(0xffffffe8,0x18);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e0c40 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0c3c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      uStack_3c = FUN_80022264(2,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0c3c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c78);
      uStack_44 = FUN_80022264(0xfffffffb,5);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0c3c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c78);
      local_74 = FLOAT_803e0c34;
      local_a8 = 0x6e;
      local_6c = 0x80180200;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      local_50 = 0xff;
      break;
    case 0x489:
      local_74 = FLOAT_803e0c58;
      local_a8 = FUN_80022264(0x32,100);
      local_50 = 0x7f;
      local_6c = 0x1180100;
      local_6e = 0x2b;
      local_68 = 0x4000000;
      break;
    case 0x48a:
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_8c = FLOAT_803e0c34 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      uStack_2c = FUN_80022264(0x1e,0x32);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0c34 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffffce,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0c34 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      local_74 = FLOAT_803e0c5c;
      local_a8 = FUN_80022264(0x32,0x46);
      local_50 = 0x7f;
      local_6c = 0x1180100;
      local_68 = 0x8000000;
      local_6e = 0x2b;
      break;
    case 0x48b:
      uStack_24 = FUN_80022264(0xffffffce,0x32);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
      local_7c = FLOAT_803e0c60;
      uStack_2c = FUN_80022264(0xffffffce,0x32);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0c3c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
      uStack_3c = FUN_80022264(0xffffffec,0);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0c38 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0c78);
      uStack_44 = FUN_80022264(0xffffffec,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0c3c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0c78);
      uStack_1c = FUN_80022264(0,10);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0c68 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c78)
                 + FLOAT_803e0c64;
      local_a8 = FUN_80022264(0xbe,0xfa);
      local_6c = 0x81088000;
      uVar2 = FUN_80022264(0,2);
      local_6e = (short)uVar2 + 0x208;
      local_58 = 0xb400;
      local_56 = 0x8000;
      local_54 = 0;
      local_64 = 0xb400;
      local_60 = 0xa000;
      local_5c = 0;
      local_68 = 0x20;
      local_50 = 0xd2;
      break;
    case 0x48c:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039d04c = FLOAT_803e0c28;
        DAT_8039d050 = FLOAT_803e0c28;
        DAT_8039d054 = FLOAT_803e0c28;
        DAT_8039d048 = FLOAT_803e0c30;
        DAT_8039d040 = 0;
        DAT_8039d042 = 0;
        DAT_8039d044 = 0;
      }
      if (param_6 == (float *)0x0) goto LAB_800c6818;
      if (*param_6 == 0.0) {
        uStack_1c = FUN_80022264(8,0x11);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_74 = FLOAT_803e0c6c *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c78);
        local_a8 = FUN_80022264(5,10);
        local_50 = 100;
        local_6c = 0x80110;
        local_68 = 0x4000800;
      }
      else if (*param_6 == 1.4013e-45) {
        uStack_1c = FUN_80022264(0xffffffce,0x32);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_8c = FLOAT_803e0c34 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c78);
        uStack_24 = FUN_80022264(0xffffffce,0x32);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_88 = FLOAT_803e0c34 *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
        uStack_2c = FUN_80022264(0,0x32);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803e0c34 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
        uStack_34 = FUN_80022264(10,0x14);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_74 = FLOAT_803e0c70 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0c78);
        local_a8 = 0x2d;
        local_50 = 0;
        local_6c = 0x880014;
        local_68 = 0x4010808;
      }
      else {
        uStack_1c = FUN_80022264(0xffffffd8,0x28);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_8c = FLOAT_803e0c34 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0c78);
        uStack_24 = FUN_80022264(0xfffffff6,0x1e);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_88 = FLOAT_803e0c58 *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0c78);
        uStack_2c = FUN_80022264(0,0x28);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803e0c58 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0c78);
        local_bc = FLOAT_803e0c28;
        local_b8 = FLOAT_803e0c28;
        local_b4 = FLOAT_803e0c28;
        local_c0 = FLOAT_803e0c30;
        local_c8[2] = 0;
        local_c8[1] = 0;
        local_c8[0] = *puVar1;
        FUN_80021b8c(local_c8,&local_8c);
        local_74 = FLOAT_803e0c34;
        local_a8 = 100;
        local_50 = 0xff;
        local_68 = 0x300800;
        local_6c = 0x3000210;
      }
      uVar2 = FUN_80022264(0x156,0x157);
      local_6e = (short)uVar2;
    }
    local_6c = local_6c | param_4;
    if (((local_6c & 1) != 0) && ((local_6c & 2) != 0)) {
      local_6c = local_6c ^ 2;
    }
    if ((local_6c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b0 != (ushort *)0x0) {
          local_80 = local_80 + *(float *)(local_b0 + 0xc);
          local_7c = local_7c + *(float *)(local_b0 + 0xe);
          local_78 = local_78 + *(float *)(local_b0 + 0x10);
        }
      }
      else {
        local_80 = local_80 + local_98;
        local_7c = local_7c + local_94;
        local_78 = local_78 + local_90;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(&local_b0,0xffffffff,(int)uVar3,0);
  }
LAB_800c6818:
  FUN_80286888();
  return;
}

