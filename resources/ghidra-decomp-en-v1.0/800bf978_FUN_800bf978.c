// Function: FUN_800bf978
// Entry: 800bf978
// Size: 5920 bytes

undefined4
FUN_800bf978(int param_1,undefined4 param_2,short *param_3,uint param_4,undefined param_5)

{
  undefined4 uVar1;
  short sVar3;
  int iVar2;
  int local_c8;
  undefined4 local_c4;
  int local_c0;
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
  uint uStack92;
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
  undefined4 local_20;
  uint uStack28;
  
  FLOAT_803db810 = FLOAT_803db810 + FLOAT_803dfd98;
  if (FLOAT_803dfda0 < FLOAT_803db810) {
    FLOAT_803db810 = FLOAT_803dfd9c;
  }
  FLOAT_803db814 = FLOAT_803db814 + FLOAT_803dfda4;
  if (FLOAT_803dfda0 < FLOAT_803db814) {
    FLOAT_803db814 = FLOAT_803dfda8;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
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
    local_98 = FLOAT_803dfdac;
    local_94 = FLOAT_803dfdac;
    local_90 = FLOAT_803dfdac;
    local_a4 = FLOAT_803dfdac;
    local_a0 = FLOAT_803dfdac;
    local_9c = FLOAT_803dfdac;
    local_8c = FLOAT_803dfdac;
    local_c0 = 0;
    local_c4 = 0xffffffff;
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
    local_c8 = param_1;
    switch(param_2) {
    case 0x352:
      local_8c = FLOAT_803dfdd0;
      local_c0 = 100;
      local_67 = 0;
      local_84 = (code *)0xa100208;
      local_86 = 0x91;
      break;
    case 0x353:
      uStack44 = FUN_800221a0(0xfffffffe,2);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      uStack52 = FUN_800221a0(0xfffffffe,2);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18);
      uStack60 = FUN_800221a0(0xffffffec,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a4 = FLOAT_803dfdd4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(0xffffffec,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803dfdd4 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0,0x50);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0x28,0x50);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803dfdd8 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      local_c0 = FUN_800221a0(0,0x17c);
      local_c0 = local_c0 + 0xb4;
      local_68 = 0xff;
      local_84 = (code *)0x80400109;
      local_86 = 0x47;
      break;
    case 0x354:
      uStack44 = FUN_800221a0(0xfffffffc,4);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      uStack52 = FUN_800221a0(0xfffffffc,4);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18);
      uStack60 = FUN_800221a0(10,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfdc4 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack92 = FUN_800221a0(0x14,0x50);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803dfdc8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      local_c0 = FUN_800221a0(0,0x118);
      local_c0 = local_c0 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x1000001;
      local_c4 = 0x284;
      local_86 = 0x208;
      break;
    case 0x355:
      local_8c = FLOAT_803dfd9c;
      local_c0 = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x580101;
      local_86 = 0x17c;
      break;
    case 0x356:
      local_8c = FLOAT_803dfdc4;
      local_c0 = 0x96;
      local_68 = 0xff;
      uStack44 = FUN_800221a0(0,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a0 = FLOAT_803dfddc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      local_84 = (code *)0x80201;
      local_86 = 0x62;
      break;
    case 0x357:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
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
      local_8c = FLOAT_803dfdcc;
      local_c0 = 0x1e;
      local_68 = 0x78;
      local_84 = (code *)0x8000201;
      local_80 = 0x20;
      local_86 = 0x71;
      break;
    default:
      return 0xffffffff;
    case 0x359:
      uStack44 = FUN_800221a0(0xffffffe2,0x1e);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      uStack52 = FUN_800221a0(0xffffffe2,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18);
      uStack60 = FUN_800221a0(0x1e,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = FLOAT_803dfdbc + (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0,100);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfdc4 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack92 = FUN_800221a0(0x14,0x50);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803dfdc8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      local_c0 = FUN_800221a0(0,0x118);
      local_c0 = local_c0 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x81008000;
      local_c4 = 0x284;
      local_86 = 0x208;
      break;
    case 0x35a:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      sVar3 = param_3[2];
      uStack44 = (int)sVar3 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfdb0 *
                 FLOAT_803dfde0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      local_c0 = 0x3c;
      local_70 = 0xff00;
      local_6e = 0xff00;
      local_6c = 0xff00;
      local_7c = (int)sVar3 << 8;
      local_74 = 0xff00;
      local_80 = 0x60;
      local_68 = (undefined)sVar3;
      local_84 = (code *)0x201;
      local_86 = 0x76;
      local_78 = local_7c;
      break;
    case 0x35b:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_8c = FLOAT_803dfd9c;
      local_c0 = 10;
      local_68 = 0xff;
      local_84 = (code *)0x580101;
      local_86 = 0xc22;
      break;
    case 0x35c:
      if (param_3 == (short *)0x0) {
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack44 = (int)*param_3 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfde4 *
                 FLOAT_803dfdc0 *
                 (FLOAT_803dfde8 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18))
      ;
      local_c0 = 10;
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
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
      }
      if (param_3 == (short *)0x0) {
        return 0xffffffff;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      uStack44 = (int)*param_3 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfde4 *
                 FLOAT_803dfdc0 *
                 (FLOAT_803dfde8 + (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18))
      ;
      local_c0 = 10;
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
        param_3 = &DAT_8039c380;
        DAT_8039c38c = FLOAT_803dfdac;
        DAT_8039c390 = FLOAT_803dfdac;
        DAT_8039c394 = FLOAT_803dfdac;
        DAT_8039c388 = FLOAT_803dfda0;
        DAT_8039c380 = 0;
        DAT_8039c382 = 0;
        DAT_8039c384 = 0;
      }
      local_8c = FLOAT_803dfdec;
      local_c0 = 0x46;
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
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = FLOAT_803dfdb4 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xffffff9c,100);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = FLOAT_803dfdb4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0xfffffff6,0x78);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_94 = FLOAT_803dfdb4 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack92 = FUN_800221a0(2,100);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a0 = FLOAT_803dfdb8 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      local_8c = FLOAT_803dfd9c;
      local_c0 = 0x3c;
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
      uStack68 = FUN_800221a0(0xffffffe2,0x1e);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xffffffe2,0x1e);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0x1e,0x28);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_94 = FLOAT_803dfdbc + (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack52 = FUN_800221a0(0,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfdc4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18);
      uStack44 = FUN_800221a0(0x14,0x50);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfdc8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      local_c0 = FUN_800221a0(0,0x118);
      local_c0 = local_c0 + 0xb4;
      local_68 = 0xfe;
      local_84 = (code *)0x81008000;
      local_86 = 0x208;
      break;
    case 0x361:
      uStack92 = FUN_800221a0(0xffffffec,0x14);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0xffffffec,0x14);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xffffffce,0x32);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(0xffffffce,0x32);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      local_8c = FLOAT_803dfd9c;
      local_c0 = 600;
      local_68 = 200;
      local_84 = (code *)0xa100100;
      local_86 = 0x62;
      break;
    case 0x362:
      uStack68 = FUN_800221a0(0xffffffec,0x14);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xffffffec,0x14);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(0xffffffce,0x32);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      uStack92 = FUN_800221a0(0xfffffff6,10);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      local_8c = FLOAT_803dfd9c;
      local_c0 = 600;
      local_68 = 200;
      local_84 = (code *)0xa100100;
      local_86 = 0x62;
      break;
    case 0x364:
      uStack28 = FUN_800221a0(5,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfe18);
      local_8c = FLOAT_803dfe10;
      local_c0 = 0x50;
      sVar3 = FUN_800221a0(0,10000);
      local_70 = sVar3 + 0x63bf;
      iVar2 = FUN_800221a0(0,10000);
      local_78 = iVar2 + 0x3cafU & 0xffff;
      local_6e = (ushort)local_78;
      local_6c = 0x3caf;
      local_7c = (uint)local_70;
      local_74 = 0x3caf;
      local_80 = 0x20;
      local_84 = FUN_80080100;
      local_86 = 0x62;
      local_68 = 0xa0;
      break;
    case 0x365:
      uStack28 = FUN_800221a0(0x6e,200);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803dfe04 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfe18);
      uStack36 = FUN_800221a0(0xfffffed4,300);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe08 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfe18);
      uStack44 = FUN_800221a0(0xfffffed4,300);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803dfe08 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      uStack52 = FUN_800221a0(1,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dfe0c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18) +
                 FLOAT_803dfd98;
      local_68 = 0xff;
      local_bc = FUN_800221a0(0,0xffff);
      local_ba = FUN_800221a0(0,0xffff);
      local_bc = FUN_800221a0(0,0xffff);
      uStack60 = FUN_800221a0(0,600);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(0,600);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0,600);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      sVar3 = FUN_800221a0(0,40000);
      local_70 = sVar3 + 0x63bf;
      iVar2 = FUN_800221a0(0,40000);
      local_78 = iVar2 + 0x3cafU & 0xffff;
      local_6e = (ushort)local_78;
      local_6c = 0x3caf;
      local_7c = (uint)local_70;
      local_74 = 0x3caf;
      local_80 = 0x20;
      local_c0 = FUN_800221a0(0,0x3c);
      local_c0 = local_c0 + 0x15e;
      local_67 = 0x10;
      local_84 = (code *)0x86000008;
      local_86 = 0x3a2;
      break;
    case 0x366:
      uStack28 = FUN_800221a0(500,1000);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_a0 = FLOAT_803dfdb0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfe18);
      uStack36 = FUN_800221a0(0xfffffed4,300);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfd9c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfe18);
      uStack44 = FUN_800221a0(0xfffffed4,300);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803dfd9c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      local_94 = FLOAT_803dfe00;
      local_8c = FLOAT_803dfdb0;
      local_c0 = 0x3c;
      local_84 = (code *)0x400000;
      local_80 = 0x100;
      local_86 = 0x62;
      local_68 = 0x50;
      break;
    case 0x367:
      uStack44 = FUN_800221a0(0xfffffe70,400);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_98 = FLOAT_803dfd9c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfe18);
      local_94 = FLOAT_803dfdf4;
      uStack52 = FUN_800221a0(0xfffffe70,400);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = FLOAT_803dfd9c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfe18);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a4 = FLOAT_803dfdf8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfe18);
      uStack68 = FUN_800221a0(100,200);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a0 = FLOAT_803dfdc0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfe18);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803dfdf8 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfe18);
      uStack84 = FUN_800221a0(5,0x19);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_8c = FLOAT_803dfdfc * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfe18);
      local_c0 = 2000;
      local_68 = 0xe6;
      local_bc = FUN_800221a0(0,0xffff);
      local_ba = FUN_800221a0(0,0xffff);
      local_bc = FUN_800221a0(0,0xffff);
      uStack92 = FUN_800221a0(0xe6,800);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_b0 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfe18);
      uStack36 = FUN_800221a0(0xe6,800);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_ac = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfe18);
      uStack28 = FUN_800221a0(0xe6,800);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfe18);
      local_80 = 0x10000000;
      local_84 = (code *)0x8f000000;
      local_86 = 0x56e;
      break;
    case 0x369:
      local_8c = FLOAT_803dfd9c;
      local_c0 = 0x46;
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
        if (local_c8 != 0) {
          local_98 = local_98 + *(float *)(local_c8 + 0x18);
          local_94 = local_94 + *(float *)(local_c8 + 0x1c);
          local_90 = local_90 + *(float *)(local_c8 + 0x20);
        }
      }
      else {
        local_98 = local_98 + local_b0;
        local_94 = local_94 + local_ac;
        local_90 = local_90 + local_a8;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_c8,0xffffffff,param_2,0);
  }
  return uVar1;
}

