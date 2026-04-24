// Function: FUN_800c11cc
// Entry: 800c11cc
// Size: 5660 bytes

undefined4
FUN_800c11cc(int param_1,undefined4 param_2,undefined2 *param_3,uint param_4,undefined param_5)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  int local_b8;
  undefined4 local_b4;
  uint local_b0;
  undefined2 local_ac;
  undefined2 local_aa;
  undefined2 local_a8;
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
  undefined2 local_76;
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
  double local_20;
  
  FLOAT_803db820 = FLOAT_803db820 + FLOAT_803dfe28;
  if (FLOAT_803dfe30 < FLOAT_803db820) {
    FLOAT_803db820 = FLOAT_803dfe2c;
  }
  FLOAT_803db824 = FLOAT_803db824 + FLOAT_803dfe34;
  if (FLOAT_803dfe30 < FLOAT_803db824) {
    FLOAT_803db824 = FLOAT_803dfe38;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
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
    local_5a = (undefined)param_2;
    local_88 = FLOAT_803dfe3c;
    local_84 = FLOAT_803dfe3c;
    local_80 = FLOAT_803dfe3c;
    local_94 = FLOAT_803dfe3c;
    local_90 = FLOAT_803dfe3c;
    local_8c = FLOAT_803dfe3c;
    local_7c = FLOAT_803dfe3c;
    local_b0 = 0;
    local_b4 = 0xffffffff;
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
    local_b8 = param_1;
    switch(param_2) {
    case 0x3b5:
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_88 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfea8);
      uStack76 = FUN_800221a0(0xfffffff6,10);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfea8);
      uStack60 = FUN_800221a0(0x1e,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfe48 + (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfea8);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dfe4c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe4c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe50 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uVar2 = FUN_800221a0(0x14,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_7c = FLOAT_803dfe54 * (float)(local_20 - DOUBLE_803dfea8);
      iVar3 = FUN_800221a0(0,0x118);
      local_b0 = iVar3 + 0xb4;
      local_58 = 0xfe;
      local_74 = 0x81008000;
      local_b4 = 0x284;
      local_76 = 0x208;
      break;
    case 0x3b6:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uStack76 = FUN_800221a0(0xf,0x23);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_90 = FLOAT_803dfe40 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfea8);
      uStack68 = FUN_800221a0(6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803dfe44 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfea8);
      local_b0 = 0x3c;
      local_58 = 0xff;
      local_74 = 0x80180100;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0x63bf;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_64 = 0xb1df;
      local_70 = 0x20;
      break;
    default:
      return 0xffffffff;
    case 0x3ba:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      uVar2 = FUN_800221a0(1,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = FLOAT_803dfe5c * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfe64 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8) +
                 FLOAT_803dfe60;
      local_b0 = 0xa0;
      local_57 = 0;
      local_74 = 0x100201;
      local_76 = 99;
      break;
    case 0x3bb:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      local_7c = FLOAT_803dfe58;
      local_b0 = 0x96;
      local_58 = 0xff;
      local_74 = 0x8000201;
      local_76 = 0x62;
      break;
    case 0x3bc:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
      }
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803dfe68 * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(10,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe68 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0,300);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe28 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      uStack52 = FUN_800221a0(0xffffff38,200);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8);
      uStack60 = FUN_800221a0(0xffffff38,200);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfea8);
      uStack68 = FUN_800221a0(4,8);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803dfe58 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfea8);
      local_b0 = 0x46;
      local_58 = 100;
      local_57 = 0;
      local_74 = 0x180108;
      local_76 = 0x2b;
      break;
    case 0x3bd:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803dfe74 * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0x14,0x1e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe78 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe74 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      uStack52 = FUN_800221a0(0xffffff6a,0x96);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8);
      local_84 = FLOAT_803dfea0;
      local_80 = FLOAT_803dfe3c;
      if (param_3 != (undefined2 *)0x0) {
        local_80 = *(float *)(param_3 + 10);
        local_84 = *(float *)(param_3 + 8);
      }
      uStack60 = FUN_800221a0(0xffffffce,0xfffffff6);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_80 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfea8) +
                 local_80;
      local_7c = FLOAT_803dfea4;
      local_b0 = 0x1e;
      local_74 = 0x108000e;
      local_76 = 0x60;
      local_58 = 0xbe;
      break;
    case 0x3be:
      uVar2 = FUN_800221a0(1,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_90 = FLOAT_803dfe9c * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0,0x3c);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfe64 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8) +
                 FLOAT_803dfe9c;
      local_b0 = 0xa0;
      local_57 = 0;
      local_74 = 0x80100201;
      local_76 = 99;
      break;
    case 0x3c0:
    case 0x3c1:
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_8c = FLOAT_803dfe84 * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0xffffffd8,0x28);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_94 = FLOAT_803dfe84 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_90 = FLOAT_803dfe68 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      local_58 = 0xff;
      local_7c = FLOAT_803dfe88;
      local_b0 = 0x8c;
      local_74 = 0x81000000;
      local_70 = 0x200000;
      local_76 = 0x26d;
      iVar3 = FUN_800221a0(0,3);
      if (iVar3 == 3) {
        uVar2 = FUN_800221a0(1,4);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_7c = FLOAT_803dfe8c * (float)(local_20 - DOUBLE_803dfea8);
        local_74 = local_74 | 0x100100;
        local_76 = 0x2b;
        local_58 = 0x9b;
        param_2 = 0x3c1;
      }
      break;
    case 0x3c2:
      if (param_3 == (undefined2 *)0x0) {
      }
      else {
        local_88 = *(float *)(param_3 + 6);
        local_80 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(6,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_7c = FLOAT_803dfe44 * (float)(local_20 - DOUBLE_803dfea8);
      local_b0 = 0x3c;
      local_58 = 0xff;
      local_74 = 0x80180108;
      local_76 = 0x5f;
      local_60 = 0xffff;
      local_5e = 0xffff;
      local_5c = 0x63bf;
      local_6c = 0xffff;
      local_68 = 0xffff;
      local_64 = 0xb1df;
      local_70 = 0x20;
      break;
    case 0x3c3:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_94 = *(float *)(param_3 + 6);
        local_90 = *(float *)(param_3 + 8);
        local_8c = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_84 = FLOAT_803dfe2c * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_80 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      local_7c = FLOAT_803dfe74;
      local_b0 = 0x3c;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3c4:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      local_b0 = (uint)(FLOAT_803dfe48 * *(float *)(param_3 + 4) + FLOAT_803dfe90);
      local_20 = (double)(longlong)(int)local_b0;
      uStack36 = local_b0 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfe94 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      local_74 = 0xe100200;
      local_76 = 0x57;
      local_88 = *(float *)(param_3 + 6);
      local_84 = *(float *)(param_3 + 8);
      local_80 = *(float *)(param_3 + 10);
      local_a0 = FLOAT_803dfe3c;
      local_9c = FLOAT_803dfe3c;
      local_98 = FLOAT_803dfe3c;
      local_ac = *param_3;
      local_aa = 0;
      local_a8 = 0;
      break;
    case 0x3c5:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      local_7c = FLOAT_803dfe78;
      local_b0 = 100;
      local_58 = 0xff;
      local_74 = 0x8100201;
      local_76 = 0x60;
      break;
    case 0x3c6:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_800221a0(0xfffffff6,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_94 = FLOAT_803dfe28 * (float)(local_20 - DOUBLE_803dfea8);
        uStack36 = FUN_800221a0(5,100);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_90 = FLOAT_803dfe74 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8)
        ;
        uStack44 = FUN_800221a0(0xfffffff6,10);
        uStack44 = uStack44 ^ 0x80000000;
        local_30 = 0x43300000;
        local_8c = FLOAT_803dfe28 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8)
        ;
      }
      else {
        local_94 = *(float *)(param_3 + 6);
        local_90 = *(float *)(param_3 + 8);
        local_8c = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_84 = FLOAT_803dfe2c * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0xfffffda8,600);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dfe3c;
      local_7c = FLOAT_803dfe78;
      local_b0 = 0x28;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3c7:
      local_7c = FLOAT_803dfe80;
      if (param_3 != (undefined2 *)0x0) {
        local_84 = *(float *)(param_3 + 8);
        local_7c = FLOAT_803dfe7c * *(float *)(param_3 + 4);
      }
      local_b0 = 0xf;
      local_58 = 0x7f;
      local_74 = 0x80210;
      local_76 = 0x4f9;
      local_57 = 0x20;
      local_60 = 0xff00;
      local_5e = 0xff00;
      local_5c = 0xff00;
      local_6c = 0xff00;
      local_68 = 0xff00;
      local_64 = 0xff00;
      local_70 = 0x2000020;
      break;
    case 0x3c9:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c3a4 = FLOAT_803dfe3c;
        DAT_8039c3a8 = FLOAT_803dfe3c;
        DAT_8039c3ac = FLOAT_803dfe3c;
        DAT_8039c3a0 = FLOAT_803dfe30;
        DAT_8039c398 = 0;
        DAT_8039c39a = 0;
        DAT_8039c39c = 0;
        param_3 = &DAT_8039c398;
      }
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803dfe7c * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0x14,0x1e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe98 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe7c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      local_80 = FLOAT_803dfe3c;
      local_88 = FLOAT_803dfe3c;
      local_84 = FLOAT_803dfe3c;
      if (param_3 != (undefined2 *)0x0) {
        local_88 = *(float *)(param_3 + 6);
        local_84 = *(float *)(param_3 + 8);
        local_80 = *(float *)(param_3 + 10);
      }
      uStack52 = FUN_800221a0(0xffffffce,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8) +
                 local_84;
      uStack60 = FUN_800221a0(0xffffffce,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfea8) +
                 local_88;
      uStack68 = FUN_800221a0(0xffffffce,0x32);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803dfe2c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfea8) +
                 local_80;
      local_7c = FLOAT_803dfe78;
      local_b0 = 0x14;
      local_74 = 0x1080006;
      local_76 = 0x60;
      local_58 = 0xa0;
      break;
    case 0x3ca:
      uVar2 = FUN_800221a0(0xffffffce,0x32);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803dfe78 * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0x1e,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe78 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xffffffce,0x32);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe78 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      uStack52 = FUN_800221a0(0,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_7c = FLOAT_803dfe64 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8) +
                 FLOAT_803dfe74;
      local_b0 = FUN_800221a0(0x32,0x46);
      local_58 = 0x7f;
      local_74 = 0x1180100;
      local_76 = 0x2b;
      break;
    case 0x3cb:
      local_7c = FLOAT_803dfe74;
      local_b0 = FUN_800221a0(0x32,100);
      local_58 = 0x7f;
      local_74 = 0x1180100;
      local_76 = 0x2b;
      break;
    case 0x3cc:
      uVar2 = FUN_800221a0(0xffffffce,0x32);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_94 = FLOAT_803dfe68 * (float)(local_20 - DOUBLE_803dfea8);
      uStack36 = FUN_800221a0(0x1e,0x32);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_90 = FLOAT_803dfe68 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfea8);
      uStack44 = FUN_800221a0(0xffffffce,0x32);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfe68 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfea8);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfe6c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfea8);
      uStack60 = FUN_800221a0(0xfffffff6,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfe6c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfea8);
      uStack68 = FUN_800221a0(0xfffffff6,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = FLOAT_803dfe6c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfea8);
      iVar3 = FUN_800221a0(0,0x14);
      local_b0 = iVar3 + 0x1e;
      local_57 = 0;
      local_58 = 0xa5;
      local_74 = 0x180108;
      uStack76 = FUN_800221a0(0x28,0x50);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_7c = FLOAT_803dfe70 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfea8);
      local_76 = 0x167;
    }
    local_74 = local_74 | param_4;
    if (((local_74 & 1) != 0) && ((local_74 & 2) != 0)) {
      local_74 = local_74 ^ 2;
    }
    if ((local_74 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b8 != 0) {
          local_88 = local_88 + *(float *)(local_b8 + 0x18);
          local_84 = local_84 + *(float *)(local_b8 + 0x1c);
          local_80 = local_80 + *(float *)(local_b8 + 0x20);
        }
      }
      else {
        local_88 = local_88 + local_a0;
        local_84 = local_84 + local_9c;
        local_80 = local_80 + local_98;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_b8,0xffffffff,param_2,0);
  }
  return uVar1;
}

