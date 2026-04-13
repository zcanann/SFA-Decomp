// Function: FUN_800c8294
// Entry: 800c8294
// Size: 4100 bytes

undefined4
FUN_800c8294(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)

{
  undefined4 uVar1;
  int local_98 [3];
  undefined2 local_8c;
  undefined2 local_8a;
  undefined2 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined2 local_56;
  uint local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined local_3a;
  undefined local_38;
  undefined local_37;
  undefined local_36;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  FLOAT_803dc4a0 = FLOAT_803dc4a0 + FLOAT_803e0d28;
  if (FLOAT_803e0d30 < FLOAT_803dc4a0) {
    FLOAT_803dc4a0 = FLOAT_803e0d2c;
  }
  FLOAT_803dc4a4 = FLOAT_803dc4a4 + FLOAT_803e0d34;
  if (FLOAT_803e0d30 < FLOAT_803dc4a4) {
    FLOAT_803dc4a4 = FLOAT_803e0d38;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
      local_80 = *(float *)(param_3 + 6);
      local_7c = *(float *)(param_3 + 8);
      local_78 = *(float *)(param_3 + 10);
      local_84 = *(undefined4 *)(param_3 + 4);
      local_88 = param_3[2];
      local_8a = param_3[1];
      local_8c = *param_3;
      local_36 = param_5;
    }
    local_54 = 0;
    local_50 = 0;
    local_3a = (undefined)param_2;
    local_68 = FLOAT_803e0d3c;
    local_64 = FLOAT_803e0d3c;
    local_60 = FLOAT_803e0d3c;
    local_74 = FLOAT_803e0d3c;
    local_70 = FLOAT_803e0d3c;
    local_6c = FLOAT_803e0d3c;
    local_5c = FLOAT_803e0d3c;
    local_98[2] = 0;
    local_98[1] = 0xffffffff;
    local_38 = 0xff;
    local_37 = 0;
    local_56 = 0;
    local_40 = 0xffff;
    local_3e = 0xffff;
    local_3c = 0xffff;
    local_4c = 0xffff;
    local_48 = 0xffff;
    local_44 = 0xffff;
    local_98[0] = param_1;
    switch(param_2) {
    case 0x6d7:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_2c = FUN_80022264(10,0x1e);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d28 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_98[2] = FUN_80022264(0x118,300);
      local_54 = 0x80180214;
      local_56 = 0x5c;
      break;
    case 0x6d8:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d28 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_98[2] = FUN_80022264(0x118,300);
      local_54 = 0x80180214;
      local_56 = 0xc79;
      break;
    case 0x6d9:
      uStack_2c = FUN_80022264(0xffffffe2,0x1e);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      uStack_24 = FUN_80022264(0xffffffe2,0x1e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(0xffffffe2,0x1e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      uStack_14 = FUN_80022264(10,0x14);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d44 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_38 = 0xff;
      local_54 = 0x80114;
      local_50 = 0x10008;
      local_56 = 0x157;
      break;
    case 0x6da:
      local_5c = FLOAT_803e0d48;
      local_98[2] = 0x14;
      local_54 = 0x80480210;
      local_56 = 0xc79;
      local_38 = 0x9d;
      break;
    case 0x6db:
      if (param_6 == 0) {
        uStack_14 = FUN_80022264(0xf,0x14);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_5c = FLOAT_803e0d54 *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
        local_98[2] = 1;
        local_54 = 0x80000;
      }
      else {
        uStack_14 = FUN_80022264(0xffffff6a,0x96);
        uStack_14 = uStack_14 ^ 0x80000000;
        local_18 = 0x43300000;
        local_74 = FLOAT_803e0d4c *
                   (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
        uStack_1c = FUN_80022264(0xffffff6a,0x96);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_6c = FLOAT_803e0d4c *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
        uStack_24 = FUN_80022264(100,400);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_70 = FLOAT_803e0d4c *
                   (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
        uStack_2c = FUN_80022264(0xf,0x14);
        uStack_2c = uStack_2c ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e0d50 *
                   (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
        local_98[2] = 0x32;
        local_40 = 0xffff;
        local_3e = 0xffff;
        local_3c = 0xffff;
        local_4c = 0xffff;
        local_48 = 0;
        local_44 = 0;
        local_54 = 0x3000200;
        local_50 = 0x200022;
      }
      local_38 = 0xff;
      local_56 = 0xc79;
      break;
    case 0x6dc:
      uStack_14 = FUN_80022264(8,10);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_70 = FLOAT_803e0d58 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(0x12,0x1c);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_5c = FLOAT_803e0d28 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      local_98[2] = FUN_80022264(0x32,100);
      local_54 = 0x80180200;
      local_56 = 0xc0b;
      local_38 = 0xff;
      break;
    case 0x6dd:
      local_5c = FLOAT_803e0d2c;
      local_98[2] = 10;
      local_38 = 0xc3;
      local_37 = 0x10;
      local_54 = 0x580110;
      local_56 = 0xc79;
      break;
    case 0x6de:
      uStack_14 = FUN_80022264(0xfffffff1,0xf);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0d5c * FLOAT_803dc4a0 *
                 (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(0xfffffff1,0xf);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0d5c * FLOAT_803dc4a0 *
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      uStack_24 = FUN_80022264(0xfffffff1,0xf);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0d5c * FLOAT_803dc4a0 *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
      local_38 = 0x7d;
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_54 = 0x3000000;
      local_50 = 0x300000;
      local_98[2] = 0x14;
      local_56 = 0xc79;
      break;
    case 0x6df:
      uStack_14 = FUN_80022264(0xfffffff1,0xf);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0d4c * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(0xfffffff1,0xf);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0d4c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      uStack_24 = FUN_80022264(0xfffffff1,0xf);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0d4c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
      local_38 = 0xff;
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d64 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_54 = 0x80200;
      local_50 = 0x100000;
      local_98[2] = 100;
      local_56 = 0x125;
      break;
    case 0x6e0:
      uStack_14 = FUN_80022264(0xfffffff1,0xf);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0d68 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(0xfffffff1,0xf);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e0d68 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      uStack_24 = FUN_80022264(0xfffffff1,0xf);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e0d68 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
      local_38 = 0xff;
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_54 = 0x2000200;
      local_50 = 0x300000;
      local_98[2] = 0x1e;
      local_56 = 0x33;
      break;
    case 0x6e1:
      local_98[2] = 0x46;
      local_5c = FLOAT_803e0d6c;
      local_40 = 0xff00;
      local_3e = 0xff00;
      local_3c = 0xff00;
      local_4c = 0xff00;
      local_48 = 0;
      local_44 = 0xff00;
      local_54 = 0x100100;
      local_50 = 0x20;
      local_38 = 0x7f;
      local_56 = 0x72;
      break;
    default:
      return 0xffffffff;
    case 0x6f2:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0xfffffff9,3);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      uStack_1c = FUN_80022264(5,0xf);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0d80);
      uStack_24 = FUN_80022264(0xfffffff9,3);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_6c = FLOAT_803e0d40 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0d80);
      uStack_2c = FUN_80022264(0x32,0x3c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e0d70 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0d80);
      local_98[2] = FUN_80022264(0x3c,0x5a);
      local_54 = 0x580004;
      local_50 = 0x400000;
      local_38 = 0xff;
      local_56 = 0xc0d;
      break;
    case 0x6f3:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d74 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x58f;
      break;
    case 0x6f4:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d78 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x4800001;
      local_38 = 0xff;
      local_56 = 0x590;
      break;
    case 0x6f5:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d74 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x403;
      break;
    case 0x6f6:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d78 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x4800001;
      local_38 = 0xff;
      local_56 = 0x404;
      break;
    case 0x6f7:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d74 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x405;
      break;
    case 0x6f8:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039d070;
        DAT_8039d07c = FLOAT_803e0d3c;
        DAT_8039d080 = FLOAT_803e0d3c;
        DAT_8039d084 = FLOAT_803e0d3c;
        DAT_8039d078 = FLOAT_803e0d30;
        DAT_8039d070 = 0;
        DAT_8039d072 = 0;
        DAT_8039d074 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack_14 = FUN_80022264(0x32,100);
      uStack_14 = uStack_14 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e0d78 * (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e0d80);
      local_98[2] = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x406;
    }
    local_54 = local_54 | param_4;
    if (((param_4 & 1) != 0) && ((param_4 & 2) != 0)) {
      local_54 = local_54 ^ 2;
    }
    if ((local_54 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_98[0] != 0) {
          local_68 = local_68 + *(float *)(local_98[0] + 0x18);
          local_64 = local_64 + *(float *)(local_98[0] + 0x1c);
          local_60 = local_60 + *(float *)(local_98[0] + 0x20);
        }
      }
      else {
        local_68 = local_68 + local_80;
        local_64 = local_64 + local_7c;
        local_60 = local_60 + local_78;
      }
    }
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_98,0xffffffff,param_2,0);
  }
  return uVar1;
}

