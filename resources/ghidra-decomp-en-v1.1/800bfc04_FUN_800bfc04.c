// Function: FUN_800bfc04
// Entry: 800bfc04
// Size: 5920 bytes

undefined4
FUN_800bfc04(int param_1,undefined4 param_2,short *param_3,uint param_4,undefined param_5)

{
  short sVar1;
  undefined4 uVar2;
  uint uVar3;
  int local_c8 [3];
  short local_bc;
  short local_ba;
  short local_b8;
  undefined4 local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined2 local_88;
  undefined2 local_86;
  code *local_84;
  undefined4 local_80;
  uint local_7c;
  uint local_78;
  undefined4 local_74;
  ushort local_70;
  ushort local_6e;
  undefined2 local_6c;
  undefined local_6a;
  undefined local_68;
  undefined local_67;
  undefined local_66;
  undefined4 local_60;
  uint uStack_5c;
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
  undefined4 local_20;
  uint uStack_1c;
  
  FLOAT_803dc470 = FLOAT_803dc470 + FLOAT_803e0a18;
  if (FLOAT_803e0a20 < FLOAT_803dc470) {
    FLOAT_803dc470 = FLOAT_803e0a1c;
  }
  FLOAT_803dc474 = FLOAT_803dc474 + FLOAT_803e0a24;
  if (FLOAT_803e0a20 < FLOAT_803dc474) {
    FLOAT_803dc474 = FLOAT_803e0a28;
  }
  if (param_1 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_b0 = *(float *)(param_3 + 6);
      local_ac = *(float *)(param_3 + 8);
      local_a8 = *(float *)(param_3 + 10);
      local_b4 = *(undefined4 *)(param_3 + 4);
      local_b8 = param_3[2];
      local_ba = param_3[1];
      local_bc = *param_3;
      local_66 = param_5;
    }
    local_84 = (code *)0x0;
    local_80 = 0;
    local_6a = (undefined)param_2;
    local_98 = FLOAT_803e0a2c;
    local_94 = FLOAT_803e0a2c;
    local_90 = FLOAT_803e0a2c;
    local_a4 = FLOAT_803e0a2c;
    local_a0 = FLOAT_803e0a2c;
    local_9c = FLOAT_803e0a2c;
    local_8c = FLOAT_803e0a2c;
    local_c8[2] = 0;
    local_c8[1] = 0xffffffff;
    local_68 = 0xff;
    local_67 = 0;
    local_86 = 0;
    local_70 = 0xffff;
    local_6e = 0xffff;
    local_6c = 0xffff;
    local_7c = 0xffff;
    local_78 = 0xffff;
    local_74 = 0xffff;
    local_88 = 0;
    local_c8[0] = param_1;
    switch(param_2) {
    case 0x352:
      local_8c = FLOAT_803e0a50;
      local_c8[2] = 100;
      local_67 = 0;
      local_84 = (code *)0xa100208;
      local_86 = 0x91;
      break;
    case 0x353:
      uStack_2c = FUN_80022264(0xfffffffe,2);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      uStack_34 = FUN_80022264(0xfffffffe,2);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98);
      uStack_3c = FUN_80022264(0xffffffec,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_a4 = FLOAT_803e0a54 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(0xffffffec,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803e0a54 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0x28,0x50);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0a58 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uVar3 = FUN_80022264(0,0x17c);
      local_c8[2] = uVar3 + 0xb4;
      local_68 = 0xff;
      local_84 = (code *)0x80400109;
      local_86 = 0x47;
      break;
    case 0x354:
      uStack_2c = FUN_80022264(0xfffffffc,4);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      uStack_34 = FUN_80022264(0xfffffffc,4);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98);
      uStack_3c = FUN_80022264(10,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0a44 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_5c = FUN_80022264(0x14,0x50);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803e0a48 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      uVar3 = FUN_80022264(0,0x118);
      local_c8[2] = uVar3 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x1000001;
      local_c8[1] = 0x284;
      local_86 = 0x208;
      break;
    case 0x355:
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x580101;
      local_86 = 0x17c;
      break;
    case 0x356:
      local_8c = FLOAT_803e0a44;
      local_c8[2] = 0x96;
      local_68 = 0xff;
      uStack_2c = FUN_80022264(0,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a0 = FLOAT_803e0a5c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      local_84 = (code *)0x80201;
      local_86 = 0x62;
      break;
    case 0x357:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_70 = (ushort)(((int)param_3[2] & 0xffU) << 8);
      local_6e = (ushort)(((int)param_3[1] & 0xffU) << 8);
      local_6c = (undefined2)(((int)*param_3 & 0xffU) << 8);
      local_7c = 0xfe00;
      local_78 = 0xfe00;
      local_74 = 0xfe00;
      local_8c = FLOAT_803e0a4c;
      local_c8[2] = 0x1e;
      local_68 = 0x78;
      local_84 = (code *)0x8000201;
      local_80 = 0x20;
      local_86 = 0x71;
      break;
    default:
      return 0xffffffff;
    case 0x359:
      uStack_2c = FUN_80022264(0xffffffe2,0x1e);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      uStack_34 = FUN_80022264(0xffffffe2,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98);
      uStack_3c = FUN_80022264(0x1e,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803e0a3c + (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(0xfffffff6,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xfffffff6,10);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0,100);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0a44 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_5c = FUN_80022264(0x14,0x50);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803e0a48 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      uVar3 = FUN_80022264(0,0x118);
      local_c8[2] = uVar3 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x81008000;
      local_c8[1] = 0x284;
      local_86 = 0x208;
      break;
    case 0x35a:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      sVar1 = param_3[2];
      uStack_2c = (int)sVar1 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0a30 *
                 FLOAT_803e0a60 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      local_c8[2] = 0x3c;
      local_70 = 0xff00;
      local_6e = 0xff00;
      local_6c = 0xff00;
      local_7c = (int)sVar1 << 8;
      local_74 = 0xff00;
      local_80 = 0x60;
      local_68 = (undefined)sVar1;
      local_84 = (code *)0x201;
      local_86 = 0x76;
      local_78 = local_7c;
      break;
    case 0x35b:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 10;
      local_68 = 0xff;
      local_84 = (code *)0x580101;
      local_86 = 0xc22;
      break;
    case 0x35c:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack_2c = (int)*param_3 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0a64 *
                 FLOAT_803e0a40 *
                 (FLOAT_803e0a68 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98)
                 );
      local_c8[2] = 10;
      local_7c = (int)*param_3 << 8;
      local_70 = (ushort)local_7c;
      local_6c = 0xff00;
      local_74 = 0xff00;
      local_80 = 0x20;
      local_68 = (undefined)param_3[2];
      local_86 = 0xc9d;
      local_78 = local_7c;
      local_6e = local_70;
      break;
    case 0x35d:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack_2c = (int)*param_3 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0a64 *
                 FLOAT_803e0a40 *
                 (FLOAT_803e0a68 + (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98)
                 );
      local_c8[2] = 10;
      local_70 = 0xff00;
      local_78 = (int)*param_3 << 8;
      local_6e = (ushort)local_78;
      local_6c = 0xff00;
      local_7c = 0xff00;
      local_74 = 0xff00;
      local_80 = 0x20;
      local_68 = (undefined)param_3[2];
      local_86 = 0xc9d;
      break;
    case 0x35e:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039cfe0;
        DAT_8039cfec = FLOAT_803e0a2c;
        DAT_8039cff0 = FLOAT_803e0a2c;
        DAT_8039cff4 = FLOAT_803e0a2c;
        DAT_8039cfe8 = FLOAT_803e0a20;
        DAT_8039cfe0 = 0;
        DAT_8039cfe2 = 0;
        DAT_8039cfe4 = 0;
      }
      local_8c = FLOAT_803e0a6c;
      local_c8[2] = 0x46;
      if (param_3 == (short *)0x0) {
        local_68 = 0xff;
      }
      else {
        local_68 = (undefined)param_3[2];
      }
      local_67 = 0;
      if (param_3 != (short *)0x0) {
        local_98 = *(float *)(param_3 + 6);
        local_94 = *(float *)(param_3 + 8);
        local_90 = *(float *)(param_3 + 10);
      }
      local_84 = (code *)0xa100200;
      local_86 = 0x7d;
      break;
    case 0x35f:
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803e0a34 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xffffff9c,100);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = FLOAT_803e0a34 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0xfffffff6,0x78);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_94 = FLOAT_803e0a34 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_5c = FUN_80022264(2,100);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803e0a38 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 0x3c;
      local_68 = 0x9b;
      local_84 = (code *)0x180201;
      local_86 = 0x5f;
      local_70 = 0xff00;
      local_6e = 0xff00;
      local_6c = 0x9b00;
      local_7c = 0x9600;
      local_78 = 0x1400;
      local_74 = 0x1400;
      local_80 = 0x20;
      break;
    case 0x360:
      uStack_44 = FUN_80022264(0xffffffe2,0x1e);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xffffffe2,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0x1e,0x28);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_94 = FLOAT_803e0a3c + (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_5c = FUN_80022264(0xffffffd8,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_34 = FUN_80022264(0,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0a44 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98);
      uStack_2c = FUN_80022264(0x14,0x50);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0a48 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      uVar3 = FUN_80022264(0,0x118);
      local_c8[2] = uVar3 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x81008000;
      local_86 = 0x208;
      break;
    case 0x361:
      uStack_5c = FUN_80022264(0xffffffec,0x14);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0xffffffec,0x14);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xffffffce,0x32);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(0xffffffce,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 600;
      local_68 = 200;
      local_84 = (code *)0xa100100;
      local_86 = 0x62;
      break;
    case 0x362:
      uStack_44 = FUN_80022264(0xffffffec,0x14);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xffffffec,0x14);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(0xffffffce,0x32);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      uStack_5c = FUN_80022264(0xfffffff6,10);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 600;
      local_68 = 200;
      local_84 = (code *)0xa100100;
      local_86 = 0x62;
      break;
    case 0x364:
      uStack_1c = FUN_80022264(5,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0a98);
      local_8c = FLOAT_803e0a90;
      local_c8[2] = 0x50;
      uVar3 = FUN_80022264(0,10000);
      local_70 = (short)uVar3 + 0x63bf;
      uVar3 = FUN_80022264(0,10000);
      local_78 = uVar3 + 0x3caf & 0xffff;
      local_6e = (ushort)(uVar3 + 0x3caf);
      local_6c = 0x3caf;
      local_7c = (uint)local_70;
      local_74 = 0x3caf;
      local_80 = 0x20;
      local_84 = FUN_80080100;
      local_86 = 0x62;
      local_68 = 0xa0;
      break;
    case 0x365:
      uStack_1c = FUN_80022264(0x6e,200);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803e0a84 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0a98);
      uStack_24 = FUN_80022264(0xfffffed4,300);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0a88 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0a98);
      uStack_2c = FUN_80022264(0xfffffed4,300);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0a88 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      uStack_34 = FUN_80022264(1,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0a8c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98)
                 + FLOAT_803e0a18;
      local_68 = 0xff;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (short)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_ba = (short)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (short)uVar3;
      uStack_3c = FUN_80022264(0,600);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(0,600);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0,600);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uVar3 = FUN_80022264(0,40000);
      local_70 = (short)uVar3 + 0x63bf;
      uVar3 = FUN_80022264(0,40000);
      local_78 = uVar3 + 0x3caf & 0xffff;
      local_6e = (ushort)(uVar3 + 0x3caf);
      local_6c = 0x3caf;
      local_7c = (uint)local_70;
      local_74 = 0x3caf;
      local_80 = 0x20;
      uVar3 = FUN_80022264(0,0x3c);
      local_c8[2] = uVar3 + 0x15e;
      local_67 = 0x10;
      local_84 = (code *)0x86000008;
      local_86 = 0x3a2;
      break;
    case 0x366:
      uStack_1c = FUN_80022264(500,1000);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803e0a30 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0a98);
      uStack_24 = FUN_80022264(0xfffffed4,300);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803e0a1c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0a98);
      uStack_2c = FUN_80022264(0xfffffed4,300);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0a1c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      local_94 = FLOAT_803e0a80;
      local_8c = FLOAT_803e0a30;
      local_c8[2] = 0x3c;
      local_84 = (code *)0x400000;
      local_80 = 0x100;
      local_86 = 0x62;
      local_68 = 0x50;
      break;
    case 0x367:
      uStack_2c = FUN_80022264(0xfffffe70,400);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803e0a1c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0a98);
      local_94 = FLOAT_803e0a74;
      uStack_34 = FUN_80022264(0xfffffe70,400);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = FLOAT_803e0a1c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a98);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_a4 = FLOAT_803e0a78 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a98);
      uStack_44 = FUN_80022264(100,200);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a0 = FLOAT_803e0a40 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a98);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0a78 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a98);
      uStack_54 = FUN_80022264(5,0x19);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803e0a7c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a98);
      local_c8[2] = 2000;
      local_68 = 0xe6;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (short)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_ba = (short)uVar3;
      uVar3 = FUN_80022264(0,0xffff);
      local_bc = (short)uVar3;
      uStack_5c = FUN_80022264(0xe6,800);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a98);
      uStack_24 = FUN_80022264(0xe6,800);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0a98);
      uStack_1c = FUN_80022264(0xe6,800);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0a98);
      local_80 = 0x10000000;
      local_84 = (code *)0x8f000000;
      local_86 = 0x56e;
      break;
    case 0x369:
      local_8c = FLOAT_803e0a1c;
      local_c8[2] = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x580101;
      local_86 = 0x17c;
    }
    local_84 = (code *)((uint)local_84 | param_4);
    if ((((uint)local_84 & 1) != 0) && ((param_4 & 2) != 0)) {
      local_84 = (code *)((uint)local_84 ^ 2);
    }
    if (((uint)local_84 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_c8[0] != 0) {
          local_98 = local_98 + *(float *)(local_c8[0] + 0x18);
          local_94 = local_94 + *(float *)(local_c8[0] + 0x1c);
          local_90 = local_90 + *(float *)(local_c8[0] + 0x20);
        }
      }
      else {
        local_98 = local_98 + local_b0;
        local_94 = local_94 + local_ac;
        local_90 = local_90 + local_a8;
      }
    }
    uVar2 = (**(code **)(*DAT_803dd6f8 + 8))(local_c8,0xffffffff,param_2,0);
  }
  return uVar2;
}

