// Function: FUN_800c8008
// Entry: 800c8008
// Size: 4100 bytes

undefined4
FUN_800c8008(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5,
            int param_6)

{
  undefined4 uVar1;
  int local_98;
  undefined4 local_94;
  undefined4 local_90;
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
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  FLOAT_803db840 = FLOAT_803db840 + FLOAT_803e00a8;
  if (FLOAT_803e00b0 < FLOAT_803db840) {
    FLOAT_803db840 = FLOAT_803e00ac;
  }
  FLOAT_803db844 = FLOAT_803db844 + FLOAT_803e00b4;
  if (FLOAT_803e00b0 < FLOAT_803db844) {
    FLOAT_803db844 = FLOAT_803e00b8;
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
    local_68 = FLOAT_803e00bc;
    local_64 = FLOAT_803e00bc;
    local_60 = FLOAT_803e00bc;
    local_74 = FLOAT_803e00bc;
    local_70 = FLOAT_803e00bc;
    local_6c = FLOAT_803e00bc;
    local_5c = FLOAT_803e00bc;
    local_90 = 0;
    local_94 = 0xffffffff;
    local_38 = 0xff;
    local_37 = 0;
    local_56 = 0;
    local_40 = 0xffff;
    local_3e = 0xffff;
    local_3c = 0xffff;
    local_4c = 0xffff;
    local_48 = 0xffff;
    local_44 = 0xffff;
    local_98 = param_1;
    switch(param_2) {
    case 0x6d7:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack44 = FUN_800221a0(10,0x1e);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00a8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_90 = FUN_800221a0(0x118,300);
      local_54 = 0x80180214;
      local_56 = 0x5c;
      break;
    case 0x6d8:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00a8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_90 = FUN_800221a0(0x118,300);
      local_54 = 0x80180214;
      local_56 = 0xc79;
      break;
    case 0x6d9:
      uStack44 = FUN_800221a0(0xffffffe2,0x1e);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      uStack36 = FUN_800221a0(0xffffffe2,0x1e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(0xffffffe2,0x1e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      uStack20 = FUN_800221a0(10,0x14);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00c4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_38 = 0xff;
      local_54 = 0x80114;
      local_50 = 0x10008;
      local_56 = 0x157;
      break;
    case 0x6da:
      local_5c = FLOAT_803e00c8;
      local_90 = 0x14;
      local_54 = 0x80480210;
      local_56 = 0xc79;
      local_38 = 0x9d;
      break;
    case 0x6db:
      if (param_6 == 0) {
        uStack20 = FUN_800221a0(0xf,0x14);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_5c = FLOAT_803e00d4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100)
        ;
        local_90 = 1;
        local_54 = 0x80000;
      }
      else {
        uStack20 = FUN_800221a0(0xffffff6a,0x96);
        uStack20 = uStack20 ^ 0x80000000;
        local_18 = 0x43300000;
        local_74 = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100)
        ;
        uStack28 = FUN_800221a0(0xffffff6a,0x96);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_6c = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100)
        ;
        uStack36 = FUN_800221a0(100,400);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_70 = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100)
        ;
        uStack44 = FUN_800221a0(0xf,0x14);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_5c = FLOAT_803e00d0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100)
        ;
        local_90 = 0x32;
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
      uStack20 = FUN_800221a0(8,10);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_70 = FLOAT_803e00d8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(0x12,0x1c);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_5c = FLOAT_803e00a8 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      local_90 = FUN_800221a0(0x32,100);
      local_54 = 0x80180200;
      local_56 = 0xc0b;
      local_38 = 0xff;
      break;
    case 0x6dd:
      local_5c = FLOAT_803e00ac;
      local_90 = 10;
      local_38 = 0xc3;
      local_37 = 0x10;
      local_54 = 0x580110;
      local_56 = 0xc79;
      break;
    case 0x6de:
      uStack20 = FUN_800221a0(0xfffffff1,0xf);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e00dc * FLOAT_803db840 *
                 (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(0xfffffff1,0xf);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e00dc * FLOAT_803db840 *
                 (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      uStack36 = FUN_800221a0(0xfffffff1,0xf);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e00dc * FLOAT_803db840 *
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100);
      local_38 = 0x7d;
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00e0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_54 = 0x3000000;
      local_50 = 0x300000;
      local_90 = 0x14;
      local_56 = 0xc79;
      break;
    case 0x6df:
      uStack20 = FUN_800221a0(0xfffffff1,0xf);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(0xfffffff1,0xf);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      uStack36 = FUN_800221a0(0xfffffff1,0xf);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e00cc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100);
      local_38 = 0xff;
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00e4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_54 = 0x80200;
      local_50 = 0x100000;
      local_90 = 100;
      local_56 = 0x125;
      break;
    case 0x6e0:
      uStack20 = FUN_800221a0(0xfffffff1,0xf);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e00e8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(0xfffffff1,0xf);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_6c = FLOAT_803e00e8 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      uStack36 = FUN_800221a0(0xfffffff1,0xf);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_70 = FLOAT_803e00e8 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100);
      local_38 = 0xff;
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00e0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_54 = 0x2000200;
      local_50 = 0x300000;
      local_90 = 0x1e;
      local_56 = 0x33;
      break;
    case 0x6e1:
      local_90 = 0x46;
      local_5c = FLOAT_803e00ec;
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
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0xfffffff9,3);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_74 = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      uStack28 = FUN_800221a0(5,0xf);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_70 = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e0100);
      uStack36 = FUN_800221a0(0xfffffff9,3);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_6c = FLOAT_803e00c0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e0100);
      uStack44 = FUN_800221a0(0x32,0x3c);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_5c = FLOAT_803e00f0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e0100);
      local_90 = FUN_800221a0(0x3c,0x5a);
      local_54 = 0x580004;
      local_50 = 0x400000;
      local_38 = 0xff;
      local_56 = 0xc0d;
      break;
    case 0x6f3:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x58f;
      break;
    case 0x6f4:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_54 = 0xc0804;
      local_50 = 0x4800001;
      local_38 = 0xff;
      local_56 = 0x590;
      break;
    case 0x6f5:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x403;
      break;
    case 0x6f6:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_54 = 0xc0804;
      local_50 = 0x4800001;
      local_38 = 0xff;
      local_56 = 0x404;
      break;
    case 0x6f7:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f4 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
      local_54 = 0xc0804;
      local_50 = 0x8800001;
      local_38 = 0xff;
      local_56 = 0x405;
      break;
    case 0x6f8:
      if (param_3 == (undefined2 *)0x0) {
        param_3 = &DAT_8039c410;
        DAT_8039c41c = FLOAT_803e00bc;
        DAT_8039c420 = FLOAT_803e00bc;
        DAT_8039c424 = FLOAT_803e00bc;
        DAT_8039c418 = FLOAT_803e00b0;
        DAT_8039c410 = 0;
        DAT_8039c412 = 0;
        DAT_8039c414 = 0;
      }
      local_68 = *(float *)(param_3 + 6);
      local_64 = *(float *)(param_3 + 8);
      local_60 = *(float *)(param_3 + 10);
      uStack20 = FUN_800221a0(0x32,100);
      uStack20 = uStack20 ^ 0x80000000;
      local_18 = 0x43300000;
      local_5c = FLOAT_803e00f8 * (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e0100);
      local_90 = 100;
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
        if (local_98 != 0) {
          local_68 = local_68 + *(float *)(local_98 + 0x18);
          local_64 = local_64 + *(float *)(local_98 + 0x1c);
          local_60 = local_60 + *(float *)(local_98 + 0x20);
        }
      }
      else {
        local_68 = local_68 + local_80;
        local_64 = local_64 + local_7c;
        local_60 = local_60 + local_78;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_98,0xffffffff,param_2,0);
  }
  return uVar1;
}

