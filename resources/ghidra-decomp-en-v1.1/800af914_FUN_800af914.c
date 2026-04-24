// Function: FUN_800af914
// Entry: 800af914
// Size: 14816 bytes

void FUN_800af914(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)

{
  ushort *puVar1;
  uint uVar2;
  int iVar3;
  undefined8 uVar4;
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
  undefined2 local_80;
  undefined2 local_7e;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  uint local_70;
  int local_6c;
  ushort local_68;
  undefined2 local_66;
  short local_64;
  undefined local_62;
  undefined local_60;
  char local_5f;
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
  
  uVar4 = FUN_8028683c();
  puVar1 = (ushort *)((ulonglong)uVar4 >> 0x20);
  iVar3 = (int)uVar4;
  FLOAT_803dc410 = FLOAT_803dc410 + FLOAT_803e03a0;
  if (FLOAT_803e03a8 < FLOAT_803dc410) {
    FLOAT_803dc410 = FLOAT_803e03a4;
  }
  FLOAT_803dc414 = FLOAT_803dc414 + FLOAT_803e03ac;
  if (FLOAT_803e03a8 < FLOAT_803dc414) {
    FLOAT_803dc414 = FLOAT_803e03b0;
  }
  if (puVar1 == (ushort *)0x0) goto LAB_800b32dc;
  if ((param_4 & 0x200000) != 0) {
    if (param_3 == (undefined2 *)0x0) goto LAB_800b32dc;
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
  local_90 = FLOAT_803e03b4;
  local_8c = FLOAT_803e03b4;
  local_88 = FLOAT_803e03b4;
  local_9c = FLOAT_803e03b4;
  local_98 = FLOAT_803e03b4;
  local_94 = FLOAT_803e03b4;
  local_84 = FLOAT_803e03b4;
  local_b8 = 0;
  local_bc = 0xffffffff;
  local_60 = 0xff;
  local_5f = '\0';
  local_7e = 0;
  local_68 = 0xffff;
  local_66 = 0xffff;
  local_64 = -1;
  local_74 = 0xffff;
  local_70 = 0xffff;
  local_6c = 0xffff;
  local_80 = 0;
  local_c0 = puVar1;
  if (iVar3 == 0x3a7) {
    local_84 = FLOAT_803e03d4;
    local_b8 = 0x50;
    local_60 = 0xff;
    local_7c = 0x1c0100;
    local_7e = 0x73;
  }
  else if (iVar3 < 0x3a7) {
    if (iVar3 == 0x395) {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cf8c = FLOAT_803e03b4;
        DAT_8039cf90 = FLOAT_803e03b4;
        DAT_8039cf94 = FLOAT_803e03b4;
        DAT_8039cf88 = FLOAT_803e03a8;
        DAT_8039cf80 = 0;
        DAT_8039cf82 = 0;
        DAT_8039cf84 = 0;
        param_3 = &DAT_8039cf80;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
        local_90 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0,0xffff);
      local_b4 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_b2 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_b4 = (undefined2)uVar2;
      local_a8 = FLOAT_803e03b4;
      local_a4 = FLOAT_803e03b4;
      local_a0 = FLOAT_803e03b4;
      uStack_2c = FUN_80022264(0x1e,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      local_b8 = FUN_80022264(0x50,100);
      local_60 = 0xff;
      local_7c = 0x6100110;
      local_7e = 0xc79;
    }
    else if (iVar3 < 0x395) {
      if (iVar3 == 0x38c) {
        local_8c = FLOAT_803e04b0;
        local_84 = FLOAT_803e04b4;
        local_b8 = 400;
        local_78 = 0x100;
        local_7e = 0x167;
        local_60 = 0x9b;
      }
      else if (iVar3 < 0x38c) {
        if (iVar3 == 0x387) {
          uStack_24 = FUN_80022264(0xffffffe7,0x19);
          uStack_24 = uStack_24 ^ 0x80000000;
          local_28 = 0x43300000;
          local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0);
          uStack_2c = FUN_80022264(1,5);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xffffffe7,0x19);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(0xfffffff8,8);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803e03b8 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          uStack_44 = FUN_80022264(10,0x14);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_98 = FLOAT_803e03a4 *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          uStack_4c = FUN_80022264(0xfffffff8,8);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          local_94 = FLOAT_803e03b8 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
          uStack_54 = FUN_80022264(0,10);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_84 = FLOAT_803e03e8 *
                     (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0) +
                     FLOAT_803e04d0;
          local_b8 = FUN_80022264(0x78,0x8c);
          local_60 = 0xff;
          local_bc = 0x385;
          local_78 = 0x200000;
          local_7c = 0x81000120;
          local_7e = 0xc0a;
        }
        else if (iVar3 < 0x387) {
          if (iVar3 == 0x385) {
            uStack_24 = FUN_80022264(2,0x14);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            local_98 = FLOAT_803e03e4 *
                       (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0);
            local_84 = FLOAT_803e04d4;
            local_b8 = 0x1e;
            local_60 = 0x9b;
            local_7c = 0x180100;
            local_7e = 0x5f;
            local_68 = 0xffff;
            uVar2 = FUN_80022264(0,50000);
            local_70 = uVar2 + 0x3caf & 0xffff;
            local_66 = (undefined2)(uVar2 + 0x3caf);
            local_64 = 0;
            local_74 = (uint)local_68;
            local_6c = 0;
            local_78 = 0x20;
          }
          else if (iVar3 < 0x385) {
            if (iVar3 < 900) goto LAB_800b32dc;
            uStack_24 = FUN_80022264(0xffffffc9,0x37);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0);
            uStack_2c = FUN_80022264(10,0xf);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
            uStack_34 = FUN_80022264(0xffffffc9,0x37);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            uStack_3c = FUN_80022264(0xfffffff8,8);
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_9c = FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
            uStack_44 = FUN_80022264(10,0x14);
            uStack_44 = uStack_44 ^ 0x80000000;
            local_48 = 0x43300000;
            local_98 = FLOAT_803e03a4 *
                       (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
            uStack_4c = FUN_80022264(0xfffffff8,8);
            uStack_4c = uStack_4c ^ 0x80000000;
            local_50 = 0x43300000;
            local_94 = FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
            uStack_54 = FUN_80022264(0,10);
            uStack_54 = uStack_54 ^ 0x80000000;
            local_58 = 0x43300000;
            local_84 = FLOAT_803e03e8 *
                       (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0) +
                       FLOAT_803e04d0;
            local_b8 = FUN_80022264(0x78,0x8c);
            local_60 = 0xff;
            local_bc = 0x385;
            local_78 = 0x200000;
            local_7c = 0x1001100;
            local_7e = 0xc0a;
          }
          else {
            uStack_24 = FUN_80022264(1,5);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0);
            uStack_2c = FUN_80022264(10,0x14);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_98 = FLOAT_803e0428 *
                       (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
            uStack_34 = FUN_80022264(0,10);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_84 = FLOAT_803e03e8 *
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0) +
                       FLOAT_803e04d8;
            local_b8 = FUN_80022264(0xe6,0x118);
            local_60 = 0x9b;
            local_7c = 0x80480200;
            local_7e = 0xc0d;
          }
        }
        else if (iVar3 == 0x38a) {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039cf8c = FLOAT_803e03b4;
            DAT_8039cf90 = FLOAT_803e03b4;
            DAT_8039cf94 = FLOAT_803e03b4;
            DAT_8039cf88 = FLOAT_803e03a8;
            DAT_8039cf80 = 0;
            DAT_8039cf82 = 0;
            DAT_8039cf84 = 0;
            param_3 = &DAT_8039cf80;
          }
          uStack_2c = FUN_80022264(0xfffffff6,0xfffffff6);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = FLOAT_803e03a4 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xffffffec,0xfffffff6);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = FLOAT_803e03a4 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(0xfffffff6,10);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_88 = FLOAT_803e03a4 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          uStack_44 = FUN_80022264(0xfffffff6,10);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_9c = FLOAT_803e045c *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          uStack_4c = FUN_80022264(0xfffffff6,10);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          local_94 = FLOAT_803e045c *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
          local_60 = 0xff;
          if (param_3 != (undefined2 *)0x0) {
            local_90 = local_90 + *(float *)(param_3 + 6);
            local_8c = local_8c + *(float *)(param_3 + 8);
            local_88 = local_88 + *(float *)(param_3 + 10);
          }
          uStack_2c = FUN_80022264(10,0x14);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_84 = FLOAT_803e04a8 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          local_b8 = 0x55;
          local_7c = 0x100200;
          local_7e = 0x125;
          uVar2 = FUN_80022264(0,0x14);
          local_5f = (char)uVar2 + '\x04';
          local_68 = 0xffff;
          uVar2 = FUN_80022264(0,10000);
          local_66 = (undefined2)(uVar2 + 0xd8ef);
          local_64 = 0;
          local_74 = local_68 / 10;
          local_70 = (uVar2 + 0xd8ef & 0xffff) / 10;
          local_6c = 0;
          local_78 = 0xa0;
        }
        else if (iVar3 < 0x38a) {
          if (iVar3 < 0x389) {
            uStack_24 = FUN_80022264(0,0x10);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0);
            uStack_2c = FUN_80022264(0xffffffd2,0x2e);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
            uStack_34 = FUN_80022264(0x10,0x1e);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803e03c8 *
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            local_84 = FLOAT_803e046c;
            local_b8 = 100;
            local_60 = 0x37;
            local_5f = '\x10';
            local_7c = 0x100;
            local_78 = 0x100;
            local_7e = 0x1fb;
          }
          else {
            if (param_3 == (undefined2 *)0x0) {
              DAT_8039cf8c = FLOAT_803e03b4;
              DAT_8039cf90 = FLOAT_803e03b4;
              DAT_8039cf94 = FLOAT_803e03b4;
              DAT_8039cf88 = FLOAT_803e03a8;
              DAT_8039cf80 = 0;
              DAT_8039cf82 = 0;
              DAT_8039cf84 = 0;
            }
            uStack_2c = FUN_80022264(0xfffffffb,5);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
            uStack_34 = FUN_80022264(1,5);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            uStack_3c = FUN_80022264(0xfffffffb,5);
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_88 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
            uStack_44 = FUN_80022264(0,600);
            uStack_44 = uStack_44 ^ 0x80000000;
            local_48 = 0x43300000;
            local_d0 = FLOAT_803e045c *
                       (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0) +
                       FLOAT_803e04c4;
            uStack_4c = FUN_80022264(0,200);
            uStack_4c = uStack_4c ^ 0x80000000;
            local_50 = 0x43300000;
            local_98 = FLOAT_803e03a0 *
                       (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0) +
                       FLOAT_803e03a8;
            uStack_54 = FUN_80022264(0,0x14);
            uStack_54 = uStack_54 ^ 0x80000000;
            local_58 = 0x43300000;
            local_98 = local_98 * local_d0;
            local_9c = (FLOAT_803e0430 *
                        (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0) +
                       FLOAT_803e03a4) * local_d0;
            uStack_24 = FUN_80022264(0,10);
            uStack_24 = uStack_24 ^ 0x80000000;
            local_28 = 0x43300000;
            local_84 = FLOAT_803e04cc *
                       (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e04e0) +
                       FLOAT_803e04c8;
            local_b8 = FUN_80022264(0xb4,200);
            local_60 = 0xff;
            local_7c = 0x3000120;
            local_78 = 0x200800;
            local_7e = 0xc0a;
            local_bc = 0x385;
          }
        }
        else {
          local_84 = FLOAT_803e04ac;
          local_b8 = 0x4b;
          local_7c = 0x82000108;
          local_78 = 0x80;
          local_7e = 0xc0a;
          local_60 = 0xff;
        }
      }
      else if (iVar3 == 0x391) {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039cf8c = FLOAT_803e03b4;
          DAT_8039cf90 = FLOAT_803e03b4;
          DAT_8039cf94 = FLOAT_803e03b4;
          DAT_8039cf88 = FLOAT_803e03a8;
          DAT_8039cf80 = 0;
          DAT_8039cf82 = 0;
          DAT_8039cf84 = 0;
          param_3 = &DAT_8039cf80;
        }
        if (param_3 == (undefined2 *)0x0) {
          local_88 = FLOAT_803e03d8;
          local_8c = FLOAT_803e03dc;
        }
        else {
          local_88 = *(float *)(param_3 + 6);
          local_8c = *(float *)(param_3 + 8);
        }
        uStack_2c = FUN_80022264(0x1e,0x28);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_94 = FLOAT_803e03ec *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0xfffffff6,10);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_9c = FLOAT_803e03b8 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(0xfffffffc,4);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_98 = FLOAT_803e03e4 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        uStack_44 = FUN_80022264(0x28,0x32);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = FLOAT_803e03f0 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
        local_b8 = FUN_80022264(0,0x3c);
        local_b8 = local_b8 + 0x50;
        local_60 = 0xff;
        local_7e = 0xc0a;
        local_78 = 0x200000;
        local_7c = 0x42000100;
      }
      else if (iVar3 < 0x391) {
        if (iVar3 == 0x38f) {
          uStack_2c = FUN_80022264(0xffffff74,0x8c);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xffffffd8,0x8c);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(0xffffff74,0x8c);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          uStack_44 = FUN_80022264(0xffffffd8,0x28);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_9c = FLOAT_803e03bc *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          uStack_4c = FUN_80022264(0xffffffd8,0x28);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          local_98 = FLOAT_803e04a4 *
                     (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
          uStack_54 = FUN_80022264(0xffffffd8,0x28);
          uStack_54 = uStack_54 ^ 0x80000000;
          local_58 = 0x43300000;
          local_94 = FLOAT_803e03bc *
                     (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
          local_84 = FLOAT_803e0464;
          local_b8 = 0x96;
          local_60 = 0xff;
          local_7e = 0x167;
          local_78 = 0x300000;
          local_7c = 0x2000110;
        }
        else if (iVar3 < 0x38f) {
          if (iVar3 < 0x38e) {
            if (param_3 == (undefined2 *)0x0) {
              DAT_8039cf8c = FLOAT_803e03b4;
              DAT_8039cf90 = FLOAT_803e03b4;
              DAT_8039cf94 = FLOAT_803e03b4;
              DAT_8039cf88 = FLOAT_803e03a8;
              DAT_8039cf80 = 0;
              DAT_8039cf82 = 0;
              DAT_8039cf84 = 0;
              param_3 = &DAT_8039cf80;
            }
            if (param_3 != (undefined2 *)0x0) {
              local_90 = *(float *)(param_3 + 6);
              local_88 = *(float *)(param_3 + 10);
            }
            local_8c = FLOAT_803e04b8;
            uStack_2c = FUN_80022264(0xfffffff6,10);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_9c = FLOAT_803e0430 *
                       (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0) +
                       FLOAT_803e03b8;
            uStack_34 = FUN_80022264(0x32,100);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            uStack_3c = FUN_80022264(0xfffffff6,1);
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_94 = FLOAT_803e0430 *
                       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0) +
                       FLOAT_803e03b8;
            local_84 = FLOAT_803e04bc;
            local_b8 = 200;
            local_7c = 0x3008000;
            local_78 = 0x200000;
            local_7e = 0x167;
            local_60 = 0xff;
          }
          else {
            uStack_2c = FUN_80022264(0xfffffff6,10);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_9c = FLOAT_803e04c0 *
                       (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0) +
                       FLOAT_803e03b8;
            uStack_34 = FUN_80022264(0x32,100);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_98 = FLOAT_803e0428 *
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            uStack_3c = FUN_80022264(0xfffffff6,1);
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_94 = FLOAT_803e04c0 *
                       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0) +
                       FLOAT_803e03b8;
            local_84 = FLOAT_803e04bc;
            local_b8 = 0x50;
            local_7c = 0x3000000;
            local_78 = 0x200000;
            local_7e = 0x167;
            local_60 = 0xff;
          }
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039cf8c = FLOAT_803e03b4;
            DAT_8039cf90 = FLOAT_803e03b4;
            DAT_8039cf94 = FLOAT_803e03b4;
            DAT_8039cf88 = FLOAT_803e03a8;
            DAT_8039cf80 = 0;
            DAT_8039cf82 = 0;
            DAT_8039cf84 = 0;
            param_3 = &DAT_8039cf80;
          }
          if (param_3 == (undefined2 *)0x0) {
            local_88 = FLOAT_803e03d8;
            local_8c = FLOAT_803e03dc;
          }
          else {
            local_88 = *(float *)(param_3 + 6);
            local_8c = *(float *)(param_3 + 8);
          }
          uStack_2c = FUN_80022264(0x1e,0x28);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803e03e0 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xfffffff6,10);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_9c = FLOAT_803e03b8 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(0xfffffffc,4);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_98 = FLOAT_803e03e4 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          uStack_44 = FUN_80022264(10,0x32);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803e03e8 *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          local_b8 = FUN_80022264(0,10);
          local_b8 = local_b8 + 0x50;
          local_60 = 0xff;
          local_7e = 0x8e;
          local_7c = 0x40180100;
        }
      }
      else if (iVar3 == 0x393) {
        uStack_2c = FUN_80022264(0xffffff38,200);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0,0x14);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(0xfffffe70,400);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_90 = FLOAT_803e03b0 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        uStack_44 = FUN_80022264(10,0x14);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_98 = FLOAT_803e0434 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
        local_84 = FLOAT_803e049c;
        local_b8 = FUN_80022264(0x212,0x2a8);
        local_60 = 0xff;
        local_7c = 0x80480208;
        local_7e = 0xc0d;
      }
      else if (iVar3 < 0x393) {
        uStack_2c = FUN_80022264(0xffffffec,0x14);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_90 = FLOAT_803e03a4 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0xffffffec,0x14);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_88 = FLOAT_803e03a4 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(0xffffffe2,0x1e);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803e0428 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        uStack_44 = FUN_80022264(0xffffffe2,0x1e);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_98 = FLOAT_803e0428 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
        uStack_4c = FUN_80022264(0xffffffe2,0x1e);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_94 = FLOAT_803e0428 *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
        uStack_54 = FUN_80022264(10,0xf);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_84 = FLOAT_803e04a0 *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
        local_b8 = FUN_80022264(0x5a,0x8c);
        local_7c = 0x80400201;
        local_5f = '\0';
        local_7e = 0x23b;
      }
      else {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039cf8c = FLOAT_803e03b4;
          DAT_8039cf90 = FLOAT_803e03b4;
          DAT_8039cf94 = FLOAT_803e03b4;
          DAT_8039cf88 = FLOAT_803e03a8;
          DAT_8039cf80 = 0;
          DAT_8039cf82 = 0;
          DAT_8039cf84 = 0;
          param_3 = &DAT_8039cf80;
        }
        if (param_3 != (undefined2 *)0x0) {
          local_88 = *(float *)(param_3 + 6);
          local_8c = *(float *)(param_3 + 8);
          local_90 = *(float *)(param_3 + 10);
        }
        uVar2 = FUN_80022264(0,0xffff);
        local_b4 = (undefined2)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_b2 = (undefined2)uVar2;
        uVar2 = FUN_80022264(0,0xffff);
        local_b4 = (undefined2)uVar2;
        local_a8 = FLOAT_803e03b4;
        local_a4 = FLOAT_803e03b4;
        local_a0 = FLOAT_803e03b4;
        uStack_2c = FUN_80022264(0x1e,0x28);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803e0498 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        local_b8 = FUN_80022264(0x1e,0x2f);
        local_60 = 0xff;
        local_7c = 0x6100100;
        local_7e = 0xc79;
      }
    }
    else if (iVar3 == 0x39e) {
      uStack_2c = FUN_80022264(0xffffffd8,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      local_60 = 0x87;
      uStack_44 = FUN_80022264(800,0x4b0);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e0440 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      local_b8 = 100;
      local_7c = 0x1480200;
      local_78 = 0x100000;
      local_7e = 0x17c;
    }
    else if (iVar3 < 0x39e) {
      if (iVar3 == 0x39a) {
        local_60 = 0xff;
        local_84 = FLOAT_803e043c;
        local_b8 = 300;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x17c;
      }
      else if (iVar3 < 0x39a) {
        if (iVar3 == 0x398) {
          local_84 = FLOAT_803e0450;
          local_b8 = 0x1e;
          local_60 = 0xff;
          local_7c = 0x80210;
          local_78 = 0x2000000;
          local_7e = 0xc0d;
        }
        else if (iVar3 < 0x398) {
          if (iVar3 < 0x397) {
            local_84 = FLOAT_803e03d4;
            local_b8 = 0x50;
            local_60 = 0xff;
            local_7c = 0x1c0100;
            local_7e = 0x159;
          }
          else {
            uStack_2c = FUN_80022264(0xfffffda8,600);
            uStack_2c = uStack_2c ^ 0x80000000;
            local_30 = 0x43300000;
            local_90 = FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
            uStack_34 = FUN_80022264(0xfffffda8,600);
            uStack_34 = uStack_34 ^ 0x80000000;
            local_38 = 0x43300000;
            local_88 = FLOAT_803e03b8 *
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
            uStack_3c = FUN_80022264(800,0x4b0);
            uStack_3c = uStack_3c ^ 0x80000000;
            local_40 = 0x43300000;
            local_98 = FLOAT_803e044c *
                       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
            local_84 = FLOAT_803e0450;
            local_b8 = 0xb4;
            local_60 = 0xff;
            local_7c = 0x80080110;
            local_bc = 0x398;
            local_7e = 0xc0d;
          }
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039cf8c = FLOAT_803e03b4;
            DAT_8039cf90 = FLOAT_803e03b4;
            DAT_8039cf94 = FLOAT_803e03b4;
            DAT_8039cf88 = FLOAT_803e03a8;
            DAT_8039cf80 = 0;
            DAT_8039cf82 = 0;
            DAT_8039cf84 = 0;
            param_3 = &DAT_8039cf80;
          }
          local_b2 = 0;
          local_b4 = 0;
          local_a8 = FLOAT_803e03b4;
          local_a4 = FLOAT_803e03b4;
          local_a0 = FLOAT_803e03b4;
          local_ac = FLOAT_803e03a8;
          if (param_3 != (undefined2 *)0x0) {
            local_90 = *(float *)(param_3 + 6);
            local_8c = FLOAT_803e0444 + *(float *)(param_3 + 8);
            local_88 = *(float *)(param_3 + 10);
            local_b4 = *param_3;
            local_b0 = param_3[2];
          }
          local_60 = 0xff;
          local_84 = FLOAT_803e0448;
          local_b8 = FUN_80022264(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x6100100;
          local_78 = 0x2000000;
          local_7e = 100;
        }
      }
      else if (iVar3 == 0x39c) {
        local_60 = 0x37;
        local_84 = FLOAT_803e0428;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x17c;
      }
      else if (iVar3 < 0x39c) {
        local_60 = 0xff;
        local_84 = FLOAT_803e03c0;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x17c;
      }
      else {
        local_60 = 0x87;
        local_84 = FLOAT_803e03c0;
        local_b8 = 0x1e;
        local_7c = 0x480200;
        local_78 = 0x2000;
        local_7e = 0x17c;
      }
    }
    else if (iVar3 == 0x3a3) {
      local_84 = FLOAT_803e03bc;
      local_b8 = 4;
      local_7c = 0x80000;
      local_78 = 0x800;
      local_7e = 100;
      local_60 = 0x9b;
    }
    else if (iVar3 < 0x3a3) {
      if (iVar3 == 0x3a1) {
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039cf8c = FLOAT_803e03b4;
          DAT_8039cf90 = FLOAT_803e03b4;
          DAT_8039cf94 = FLOAT_803e03b4;
          DAT_8039cf88 = FLOAT_803e03a8;
          DAT_8039cf80 = 0;
          DAT_8039cf82 = 0;
          DAT_8039cf84 = 0;
          param_3 = &DAT_8039cf80;
        }
        if (param_3 == (undefined2 *)0x0) goto LAB_800b32dc;
        local_90 = *(float *)(param_3 + 6);
        local_8c = FLOAT_803e0424 + *(float *)(param_3 + 8);
        local_88 = *(float *)(param_3 + 10);
        uStack_2c = FUN_80022264(0x14,0x1e);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_94 = FLOAT_803e03a4 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0xffffffec,0x14);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_9c = FLOAT_803e0428 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(0xffffffec,0x14);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_98 = FLOAT_803e0428 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        local_cc = FLOAT_803e03b4;
        local_c8 = FLOAT_803e03b4;
        local_c4 = FLOAT_803e03b4;
        local_d0 = FLOAT_803e03a8;
        local_d4 = puVar1[2];
        local_d6 = puVar1[1];
        local_d8 = *puVar1;
        FUN_80021b8c(&local_d8,&local_9c);
        local_84 = FLOAT_803e03c0;
        local_b8 = 0x32;
        local_60 = 0xff;
        local_7e = 0x167;
        local_78 = 0x200000;
        local_7c = 0x2000110;
      }
      else if (iVar3 < 0x3a1) {
        if (iVar3 < 0x3a0) {
          uStack_2c = FUN_80022264(10,0xe);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_98 = FLOAT_803e0434 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          local_84 = FLOAT_803e0438;
          local_b8 = 1;
          local_60 = 0x23;
          local_78 = 2;
          local_7e = 100;
        }
        else {
          if (param_3 == (undefined2 *)0x0) {
            DAT_8039cf8c = FLOAT_803e03b4;
            DAT_8039cf90 = FLOAT_803e03b4;
            DAT_8039cf94 = FLOAT_803e03b4;
            DAT_8039cf88 = FLOAT_803e03a8;
            DAT_8039cf80 = 0;
            DAT_8039cf82 = 0;
            DAT_8039cf84 = 0;
            param_3 = &DAT_8039cf80;
          }
          if (param_3 == (undefined2 *)0x0) goto LAB_800b32dc;
          local_90 = *(float *)(param_3 + 6);
          local_8c = FLOAT_803e0424 + *(float *)(param_3 + 8);
          local_88 = *(float *)(param_3 + 10);
          uStack_2c = FUN_80022264(0x14,0x1e);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803e042c *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xffffffec,0x14);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_9c = FLOAT_803e03e0 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(2,6);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_98 = FLOAT_803e0430 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          local_cc = FLOAT_803e03b4;
          local_c8 = FLOAT_803e03b4;
          local_c4 = FLOAT_803e03b4;
          local_d0 = FLOAT_803e03a8;
          local_d4 = puVar1[2];
          local_d6 = puVar1[1];
          local_d8 = *puVar1;
          FUN_80021b8c(&local_d8,&local_9c);
          uStack_44 = FUN_80022264(8,0x14);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803e03e4 *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          local_b8 = FUN_80022264(0x3c,0x78);
          local_7c = 0x80180000;
          local_78 = 0x1400020;
          local_7e = 0xc0b;
          local_60 = 0x7f;
          local_68 = 0xffff;
          local_66 = 0xffff;
          local_64 = -1;
          local_74 = 0x3caf;
          local_70 = 0x3caf;
          local_6c = 0x3caf;
        }
      }
      else {
LAB_800b0378:
        if (param_3 == (undefined2 *)0x0) {
          DAT_8039cf8c = FLOAT_803e03b4;
          DAT_8039cf90 = FLOAT_803e03b4;
          DAT_8039cf94 = FLOAT_803e03b4;
          DAT_8039cf88 = FLOAT_803e03a8;
          DAT_8039cf80 = 0;
          DAT_8039cf82 = 0;
          DAT_8039cf84 = 0;
          param_3 = &DAT_8039cf80;
        }
        if (param_3 == (undefined2 *)0x0) goto LAB_800b32dc;
        uStack_2c = FUN_80022264(0xffffff9c,100);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = *(float *)(param_3 + 4) *
                   FLOAT_803e040c *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0x50,0x8c);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_98 = *(float *)(param_3 + 4) *
                   FLOAT_803e0410 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(0xffffff9c,100);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_94 = *(float *)(param_3 + 4) *
                   FLOAT_803e0414 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        uStack_44 = FUN_80022264(0xffffff9c,100);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_90 = FLOAT_803e0418 *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
        local_8c = FLOAT_803e03dc;
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_88 = FLOAT_803e041c *
                   (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
        uStack_54 = FUN_80022264(0x16,0x46);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_84 = *(float *)(param_3 + 4) *
                   FLOAT_803e0420 *
                   (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
        local_b8 = FUN_80022264(0xe,0x30);
        local_b8 = local_b8 + 0x29;
        local_7e = 0x60;
        local_68 = 0xef75;
        local_66 = 0xc26e;
        local_64 = 0x4aab;
        local_74 = 0xfe9f;
        local_70 = 0x796c;
        local_6c = 0x57a0;
        uVar2 = FUN_80022264(0x29,100);
        local_60 = (undefined)uVar2;
        local_7c = 0x80080108;
        if (iVar3 == 0x3a2) {
          local_7c = 0xa0080108;
        }
        local_78 = 0x8400820;
      }
    }
    else if (iVar3 == 0x3a5) {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cf8c = FLOAT_803e03b4;
        DAT_8039cf90 = FLOAT_803e03b4;
        DAT_8039cf94 = FLOAT_803e03b4;
        DAT_8039cf88 = FLOAT_803e03a8;
        DAT_8039cf80 = 0;
        DAT_8039cf82 = 0;
        DAT_8039cf84 = 0;
        param_3 = &DAT_8039cf80;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_88 = FLOAT_803e03d8;
        local_8c = FLOAT_803e03dc;
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
      }
      uStack_44 = FUN_80022264(0x1e,0x28);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e03e0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
      uStack_54 = FUN_80022264(0xfffffffc,4);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
      uStack_3c = FUN_80022264(10,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e03e8 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      local_b8 = FUN_80022264(0,10);
      local_b8 = local_b8 + 0x50;
      local_60 = 0xff;
      local_7e = 0x8e;
      local_7c = 0x40180100;
    }
    else if (iVar3 < 0x3a5) {
      uStack_3c = FUN_80022264(0x19,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e03f4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      uStack_44 = FUN_80022264(0x42,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e03f8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      uStack_4c = FUN_80022264(0x11,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_94 = FLOAT_803e03fc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
      uStack_54 = FUN_80022264(0xffffff9c,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_90 = FLOAT_803e0400 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
      FUN_80022264(0xffffff9c,100);
      local_8c = FLOAT_803e03b4;
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0404 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      uStack_2c = FUN_80022264(0x27,0x50);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0408 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      local_b8 = FUN_80022264(0x14,0x20);
      local_b8 = local_b8 + 0xdb;
      local_7e = 0x20c;
      local_68 = 0xe2f5;
      local_66 = 0x5308;
      local_64 = 0x42d9;
      local_74 = 0x8afe;
      local_70 = 0x5866;
      local_6c = 0x40c3;
      uVar2 = FUN_80022264(0xd,0x53);
      local_60 = (undefined)uVar2;
      local_7c = 0x480208;
      local_78 = 0x8002820;
    }
    else {
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cf8c = FLOAT_803e03b4;
        DAT_8039cf90 = FLOAT_803e03b4;
        DAT_8039cf94 = FLOAT_803e03b4;
        DAT_8039cf88 = FLOAT_803e03a8;
        DAT_8039cf80 = 0;
        DAT_8039cf82 = 0;
        DAT_8039cf84 = 0;
        param_3 = &DAT_8039cf80;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_88 = FLOAT_803e03d8;
        local_8c = FLOAT_803e03dc;
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_8c = *(float *)(param_3 + 8);
      }
      uStack_3c = FUN_80022264(0x1e,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803e03ec * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803e03b8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      uStack_4c = FUN_80022264(0xfffffffc,4);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = FLOAT_803e03e4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
      uStack_54 = FUN_80022264(0x28,0x32);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_84 = FLOAT_803e03f0 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
      local_b8 = FUN_80022264(0,0x3c);
      local_b8 = local_b8 + 0x50;
      local_60 = 0xff;
      local_7e = 0xc0a;
      local_78 = 0x200000;
      local_7c = 0x42000100;
    }
  }
  else if (iVar3 == 0x5ed) {
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039cf8c = FLOAT_803e03b4;
      DAT_8039cf90 = FLOAT_803e03b4;
      DAT_8039cf94 = FLOAT_803e03b4;
      DAT_8039cf88 = FLOAT_803e03a8;
      DAT_8039cf80 = 0;
      DAT_8039cf82 = 0;
      DAT_8039cf84 = 0;
      param_3 = &DAT_8039cf80;
    }
    local_b2 = 0;
    local_b4 = 0;
    local_a8 = FLOAT_803e03b4;
    local_a4 = FLOAT_803e03b4;
    local_a0 = FLOAT_803e03b4;
    local_ac = FLOAT_803e03a8;
    if (param_3 != (undefined2 *)0x0) {
      local_90 = *(float *)(param_3 + 6);
      local_8c = FLOAT_803e0444 + *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_b4 = *param_3;
      local_b0 = param_3[2];
    }
    local_60 = 0xff;
    local_84 = FLOAT_803e0448;
    local_b8 = 0x3c;
    local_7c = 0x6100100;
    local_7e = 0x5fe;
  }
  else if (iVar3 < 0x5ed) {
    if (iVar3 == 0x5e4) {
      uStack_2c = FUN_80022264(0x19,0x23);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e047c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      local_b8 = 0xf0;
      local_60 = 0x55;
      local_7c = 0x480000;
      local_78 = 0x100;
      local_7e = 0x156;
    }
    else if (iVar3 < 0x5e4) {
      if (iVar3 == 0x5df) {
        uStack_2c = FUN_80022264(0xfffffff4,0xc);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0xfffffff4,0xc);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        uStack_3c = FUN_80022264(5,0xf);
        uStack_3c = uStack_3c ^ 0x80000000;
        local_40 = 0x43300000;
        local_9c = FLOAT_803e0484 *
                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
        local_98 = local_8c / FLOAT_803e0488;
        local_94 = local_88 / FLOAT_803e0488;
        uStack_44 = FUN_80022264(5,0xf);
        uStack_44 = uStack_44 ^ 0x80000000;
        local_48 = 0x43300000;
        local_84 = FLOAT_803e048c *
                   (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
        local_b8 = 0xfa;
        local_60 = 0x9b;
        local_7c = 0x480100;
        local_7e = 0x528;
      }
      else if (iVar3 < 0x5df) {
        if (iVar3 == 0x5dd) {
          uStack_2c = FUN_80022264(0xfffffff4,0xc);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xfffffff4,0xc);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(5,0xf);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803e0484 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          local_98 = local_8c / FLOAT_803e0488;
          local_94 = local_88 / FLOAT_803e0488;
          uStack_44 = FUN_80022264(5,0xf);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803e048c *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          local_b8 = 0xfa;
          local_60 = 0x9b;
          local_7c = 0x480100;
          local_7e = 0xc79;
        }
        else {
          if (iVar3 < 0x5dd) {
            if (0x3a8 < iVar3) goto LAB_800b32dc;
            goto LAB_800b0378;
          }
          uStack_2c = FUN_80022264(0xfffffff4,0xc);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_88 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xfffffff4,0xc);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_8c = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          uStack_3c = FUN_80022264(5,0xf);
          uStack_3c = uStack_3c ^ 0x80000000;
          local_40 = 0x43300000;
          local_9c = FLOAT_803e0484 *
                     (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
          local_98 = local_8c / FLOAT_803e0488;
          local_94 = local_88 / FLOAT_803e0488;
          uStack_44 = FUN_80022264(5,0xf);
          uStack_44 = uStack_44 ^ 0x80000000;
          local_48 = 0x43300000;
          local_84 = FLOAT_803e048c *
                     (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
          local_b8 = 0xfa;
          local_60 = 0x9b;
          local_7c = 0x480100;
          local_7e = 0x166;
        }
      }
      else if (iVar3 == 0x5e2) {
        uStack_2c = FUN_80022264(0xffffff9c,100);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = FLOAT_803e0490 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        local_98 = FLOAT_803e03b4;
        local_94 = FLOAT_803e03b4;
        local_90 = FLOAT_803e03b4;
        local_8c = FLOAT_803e03b4;
        local_88 = FLOAT_803e03b4;
        local_84 = FLOAT_803e0494;
        local_b8 = 0x39;
        local_7e = 0xc75;
        local_68 = 0x7fff;
        local_66 = 0x7fff;
        local_64 = 0x7fff;
        local_74 = 0x7fff;
        local_70 = 0x7fff;
        local_6c = 0x7fff;
        local_60 = 0xff;
        local_7c = 0x80500100;
        local_78 = 0x8000800;
      }
      else if (iVar3 < 0x5e2) {
        if (iVar3 < 0x5e1) {
          uStack_2c = FUN_80022264(0xffffff9c,100);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_9c = FLOAT_803e0490 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          local_98 = FLOAT_803e03b4;
          local_94 = FLOAT_803e03b4;
          local_90 = FLOAT_803e03b4;
          local_8c = FLOAT_803e03b4;
          local_88 = FLOAT_803e03b4;
          local_84 = FLOAT_803e0494;
          local_b8 = 0x39;
          local_7e = 0xc76;
          local_68 = 0x7fff;
          local_66 = 0x7fff;
          local_64 = 0x7fff;
          local_74 = 0x7fff;
          local_70 = 0x7fff;
          local_6c = 0x7fff;
          local_60 = 0xff;
          local_7c = 0x80500100;
          local_78 = 0x8000800;
        }
        else {
          uStack_2c = FUN_80022264(0xffffff9c,100);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_9c = FLOAT_803e0490 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          local_98 = FLOAT_803e03b4;
          local_94 = FLOAT_803e03b4;
          local_90 = FLOAT_803e03b4;
          local_8c = FLOAT_803e03b4;
          local_88 = FLOAT_803e03b4;
          local_84 = FLOAT_803e0494;
          local_b8 = 0x39;
          local_7e = 0xc74;
          local_68 = 0x7fff;
          local_66 = 0x7fff;
          local_64 = 0x7fff;
          local_74 = 0x7fff;
          local_70 = 0x7fff;
          local_6c = 0x7fff;
          local_60 = 0xff;
          local_7c = 0x80500100;
          local_78 = 0x8000800;
        }
      }
      else {
        uStack_2c = FUN_80022264(0x19,0x23);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803e047c *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        local_b8 = 0xf0;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x156;
      }
    }
    else if (iVar3 == 0x5e9) {
      local_84 = FLOAT_803e03d0;
      local_b8 = 0x14;
      local_60 = 0xff;
      local_7c = 0x480200;
      local_78 = 0x2000000;
      local_7e = 0x26c;
    }
    else if (iVar3 < 0x5e9) {
      if (iVar3 == 0x5e7) {
        uStack_2c = FUN_80022264(0x19,0x23);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_84 = FLOAT_803e047c *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        local_b8 = 6;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_78 = 0x100;
        local_7e = 0x156;
      }
      else if (iVar3 < 0x5e7) {
        if (iVar3 < 0x5e6) {
          local_84 = FLOAT_803e0480;
          local_b8 = 0xf0;
          local_60 = 0xb9;
          local_7c = 0x480000;
          local_7e = 0x156;
        }
        else {
          uStack_2c = FUN_80022264(0x19,0x23);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_84 = FLOAT_803e047c *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          local_b8 = 300;
          local_60 = 0x55;
          local_7c = 0x480000;
          local_78 = 0x200;
          local_7e = 0x156;
        }
      }
      else {
        local_84 = FLOAT_803e0480;
        local_b8 = 6;
        local_60 = 0x55;
        local_7c = 0x480000;
        local_7e = 0x156;
      }
    }
    else if (iVar3 == 0x5eb) {
      uStack_2c = FUN_80022264(0xb4,200);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_94 = FLOAT_803e0478 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_9c = FLOAT_803e0470 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      uStack_3c = FUN_80022264(0,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      local_60 = 0x9b;
      local_84 = FLOAT_803e042c;
      local_b8 = FUN_80022264(0x8c,0xa5);
      local_7c = 0x81100000;
      local_78 = 0x408020;
      local_68 = 2000;
      local_66 = 2000;
      uVar2 = FUN_80022264(0xffffec78,5000);
      local_64 = (short)uVar2 + 10000;
      local_74 = 8000;
      local_70 = 8000;
      uVar2 = FUN_80022264(0xffffec78,5000);
      local_6c = uVar2 + 12000;
      local_7e = 0x639;
    }
    else {
      if (0x5ea < iVar3) goto LAB_800b32dc;
      uStack_2c = FUN_80022264(0xffffffe7,0x19);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      uStack_34 = FUN_80022264(0xffffffe7,0x19);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      local_60 = 0x9b;
      local_84 = FLOAT_803e0430;
      local_b8 = FUN_80022264(0x46,100);
      local_7c = 0x81100000;
      local_78 = 0x408020;
      local_68 = 2000;
      local_66 = 2000;
      uVar2 = FUN_80022264(0xffffec78,5000);
      local_64 = (short)uVar2 + 20000;
      local_74 = 8000;
      local_70 = 8000;
      uVar2 = FUN_80022264(0xffffec78,5000);
      local_6c = uVar2 + 32000;
      local_7e = 0x639;
    }
  }
  else if (iVar3 == 0x5f6) {
    local_60 = 0xff;
    local_84 = FLOAT_803e0458;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 0x202;
    local_7e = 0x26c;
    (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0xff;
    local_84 = FLOAT_803e045c;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 2;
    local_7e = 0x528;
    (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0x37;
    local_84 = FLOAT_803e0430;
    local_b8 = 10;
    local_7c = 0x480000;
    local_78 = 2;
    local_7e = 0x528;
    (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0,0x5f6,0);
    local_60 = 0x87;
    local_84 = FLOAT_803e045c;
    local_b8 = 10;
    local_7c = 0x480200;
    local_78 = 0x2002;
    local_7e = 0x528;
  }
  else if (iVar3 < 0x5f6) {
    if (iVar3 == 0x5f2) {
      local_60 = 0x37;
      local_84 = FLOAT_803e0428;
      local_b8 = 300;
      local_7c = 0x480000;
      local_7e = 0x528;
    }
    else if (iVar3 < 0x5f2) {
      if (iVar3 == 0x5f0) {
        local_60 = 0xff;
        local_84 = FLOAT_803e043c;
        local_b8 = 300;
        local_7c = 0x480000;
        local_78 = 0x200;
        local_7e = 0x26c;
      }
      else if (iVar3 < 0x5f0) {
        if (iVar3 < 0x5ef) {
          uStack_2c = FUN_80022264(0xffffffd8,0x28);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_94 = FLOAT_803e0470 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xffffffd8,0x28);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_98 = FLOAT_803e0470 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          local_60 = 0xff;
          local_84 = FLOAT_803e0474;
          local_b8 = FUN_80022264(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x2000100;
          local_78 = 0x200;
          local_7e = 0x33;
        }
        else {
          uStack_2c = FUN_80022264(0xfffffe70,400);
          uStack_2c = uStack_2c ^ 0x80000000;
          local_30 = 0x43300000;
          local_90 = FLOAT_803e03a0 *
                     (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
          uStack_34 = FUN_80022264(0xfffffe70,400);
          uStack_34 = uStack_34 ^ 0x80000000;
          local_38 = 0x43300000;
          local_88 = FLOAT_803e03a0 *
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
          local_98 = FLOAT_803e0468;
          local_60 = 0x9b;
          local_84 = FLOAT_803e046c;
          local_b8 = FUN_80022264(0,10);
          local_b8 = local_b8 + 0x3c;
          local_7c = 0x80100;
          local_78 = 0x100;
          local_7e = 0x3f2;
        }
      }
      else {
        local_60 = 0xff;
        local_84 = FLOAT_803e03c0;
        local_b8 = 300;
        local_7c = 0x480000;
        local_7e = 0x528;
      }
    }
    else if (iVar3 == 0x5f4) {
      uStack_2c = FUN_80022264(0xffffff38,200);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      uStack_34 = FUN_80022264(0xffffff38,200);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      uStack_3c = FUN_80022264(300,400);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803e0460 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e04e0);
      local_60 = 0xff;
      local_84 = FLOAT_803e0460;
      local_b8 = 0x8c;
      local_7c = 0x480100;
      local_7e = 0x528;
    }
    else if (iVar3 < 0x5f4) {
      local_60 = 0x87;
      local_84 = FLOAT_803e03c0;
      local_b8 = 0x1e;
      local_7c = 0x480200;
      local_78 = 0x2000;
      local_7e = 0x528;
    }
    else {
      uStack_2c = FUN_80022264(0xfffffc7c,900);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_9c = FLOAT_803e0460 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
      uStack_34 = FUN_80022264(0xfffffc7c,900);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e0460 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
      local_60 = 0xff;
      local_84 = FLOAT_803e0464;
      local_b8 = 0x3c;
      local_7c = 0x110;
      local_78 = 0x100;
      local_7e = 0xe4;
    }
  }
  else if (iVar3 == 0x5fb) {
    local_84 = FLOAT_803e03b8;
    local_b8 = 10;
    local_60 = 0xff;
    local_7e = 0xe7;
  }
  else if (iVar3 < 0x5fb) {
    if (iVar3 == 0x5f9) {
      uStack_44 = FUN_80022264(0xfffffda8,600);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803e03c8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      uStack_4c = FUN_80022264(0xfffffda8,600);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e03c8 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
      uStack_54 = FUN_80022264(800,0x4b0);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = FLOAT_803e03cc * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
      local_84 = FLOAT_803e03d0;
      local_b8 = 0xb4;
      local_60 = 0xff;
      local_7c = 0x80480100;
      local_78 = 0x2000000;
      local_bc = 0x5e9;
      local_7e = 0x26c;
    }
    else if (iVar3 < 0x5f9) {
      if (iVar3 < 0x5f8) {
        local_60 = 0xff;
        local_84 = FLOAT_803e0454;
        local_b8 = 0x73;
        local_7c = 0x8100110;
        local_78 = 0x2000000;
        local_7e = 0x77;
      }
      else {
        uStack_2c = FUN_80022264(0xffffffd8,0x28);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_9c = FLOAT_803e0470 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
        uStack_34 = FUN_80022264(0xffffffd8,0x28);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_98 = FLOAT_803e0470 *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e04e0);
        local_60 = 0xff;
        local_84 = FLOAT_803e0474;
        local_b8 = FUN_80022264(0,10);
        local_b8 = local_b8 + 0x3c;
        local_7c = 0x2000100;
        local_78 = 0x400;
        local_7e = 0x33;
      }
    }
    else {
      uStack_54 = FUN_80022264(0xfffffda8,600);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_90 = FLOAT_803e03bc * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e04e0);
      uStack_4c = FUN_80022264(0xfffffda8,600);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_88 = FLOAT_803e03bc * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e04e0);
      uStack_44 = FUN_80022264(800,0x4b0);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e03c0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e04e0);
      local_84 = FLOAT_803e03c4;
      local_b8 = 0x28;
      local_60 = 0xff;
      local_78 = 0x200000;
      local_7e = 0x26c;
    }
  }
  else if (iVar3 == 0x5fd) {
    if (param_3 == (undefined2 *)0x0) {
      DAT_8039cf8c = FLOAT_803e03b4;
      DAT_8039cf90 = FLOAT_803e03b4;
      DAT_8039cf94 = FLOAT_803e03b4;
      DAT_8039cf88 = FLOAT_803e03a8;
      DAT_8039cf80 = 0;
      DAT_8039cf82 = 0;
      DAT_8039cf84 = 0;
      param_3 = &DAT_8039cf80;
    }
    local_b2 = 0;
    local_b4 = 0;
    local_a8 = FLOAT_803e03b4;
    local_a4 = FLOAT_803e03b4;
    local_a0 = FLOAT_803e03b4;
    local_ac = FLOAT_803e03a8;
    if (param_3 != (undefined2 *)0x0) {
      local_90 = *(float *)(param_3 + 6);
      local_8c = FLOAT_803e0444 + *(float *)(param_3 + 8);
      local_88 = *(float *)(param_3 + 10);
      local_b4 = *param_3;
      local_b0 = param_3[2];
    }
    local_60 = 0xff;
    uStack_2c = FUN_80022264(1,3);
    uStack_2c = uStack_2c ^ 0x80000000;
    local_30 = 0x43300000;
    local_84 = FLOAT_803e0448 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e04e0);
    local_b8 = FUN_80022264(0,100);
    local_b8 = local_b8 + 0x78;
    local_7c = 0x6100000;
    local_78 = 0x8000;
    local_7e = 0x5ff;
  }
  else {
    if (0x5fc < iVar3) goto LAB_800b32dc;
    local_84 = FLOAT_803e03b8;
    local_b8 = 10;
    local_60 = 0xff;
    local_7e = 0x5c;
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
  (**(code **)(*DAT_803dd6f8 + 8))(&local_c0,0xffffffff,iVar3,0);
LAB_800b32dc:
  FUN_80286888();
  return;
}

