// Function: FUN_800b319c
// Entry: 800b319c
// Size: 15400 bytes

undefined4 FUN_800b319c(int param_1,int param_2,undefined2 *param_3,uint param_4,undefined param_5)

{
  undefined4 uVar1;
  uint uVar2;
  int iVar3;
  short sVar4;
  int local_138;
  undefined4 local_134;
  int local_130;
  undefined2 local_12c;
  undefined2 local_12a;
  undefined2 local_128;
  undefined4 local_124;
  float local_120;
  float local_11c;
  float local_118;
  float local_114;
  float local_110;
  float local_10c;
  float local_108;
  float local_104;
  float local_100;
  float local_fc;
  undefined2 local_f8;
  short local_f6;
  code *local_f4;
  uint local_f0;
  uint local_ec;
  uint local_e8;
  uint local_e4;
  ushort local_e0;
  ushort local_de;
  undefined2 local_dc;
  undefined local_da;
  undefined local_d8;
  undefined local_d7;
  undefined local_d6;
  undefined4 local_d0;
  uint uStack204;
  double local_c8;
  double local_c0;
  undefined4 local_b8;
  uint uStack180;
  double local_b0;
  double local_a8;
  longlong local_a0;
  longlong local_98;
  undefined4 local_90;
  uint uStack140;
  longlong local_88;
  longlong local_80;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  double local_58;
  double local_50;
  undefined4 local_48;
  uint uStack68;
  double local_40;
  double local_38;
  undefined4 local_30;
  uint uStack44;
  double local_28;
  double local_20;
  double local_18;
  
  FLOAT_803db7c0 = FLOAT_803db7c0 + FLOAT_803df870;
  if (FLOAT_803df878 < FLOAT_803db7c0) {
    FLOAT_803db7c0 = FLOAT_803df874;
  }
  FLOAT_803db7c4 = FLOAT_803db7c4 + FLOAT_803df87c;
  if (FLOAT_803df878 < FLOAT_803db7c4) {
    FLOAT_803db7c4 = FLOAT_803df880;
  }
  if (param_1 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        return 0xffffffff;
      }
      local_120 = *(float *)(param_3 + 6);
      local_11c = *(float *)(param_3 + 8);
      local_118 = *(float *)(param_3 + 10);
      local_124 = *(undefined4 *)(param_3 + 4);
      local_128 = param_3[2];
      local_12a = param_3[1];
      local_12c = *param_3;
      local_d6 = param_5;
    }
    local_f4 = (code *)0x0;
    local_f0 = 0;
    local_da = (undefined)param_2;
    local_108 = FLOAT_803df884;
    local_104 = FLOAT_803df884;
    local_100 = FLOAT_803df884;
    local_114 = FLOAT_803df884;
    local_110 = FLOAT_803df884;
    local_10c = FLOAT_803df884;
    local_fc = FLOAT_803df884;
    local_130 = 0;
    local_134 = 0xffffffff;
    local_d8 = 0xff;
    local_d7 = 0;
    local_f6 = 0;
    local_e0 = 0xffff;
    local_de = 0xffff;
    local_dc = 0xffff;
    local_ec = 0xffff;
    local_e8 = 0xffff;
    local_e4 = 0xffff;
    local_f8 = 0;
    local_138 = param_1;
    switch(param_2) {
    case 600:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df998 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df998 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df998 * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df9ac;
      local_130 = FUN_800221a0(0x50,0x82);
      local_d8 = 0x9b;
      local_f4 = (code *)0x180200;
      local_f6 = 0x7b;
      break;
    default:
      return 0xffffffff;
    case 0x25b:
      local_fc = FLOAT_803df954;
      local_130 = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      local_f6 = 0x7b;
      break;
    case 0x25c:
    case 0x269:
    case 0x27d:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df8b4 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df8fc * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(10,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df958 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df95c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe,0x12);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df960 * (float)(local_38 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df964;
      local_130 = FUN_800221a0(0x28,0x50);
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25c) {
        local_f6 = 0x7a;
        local_134 = 0x25d;
      }
      else if (param_2 == 0x272) {
        local_f6 = 0x202;
        local_134 = 0x273;
      }
      else if (param_2 == 0x27d) {
        local_f6 = 0x7a;
        local_134 = 0x27e;
      }
      else {
        local_f6 = 0x1fe;
        local_134 = 0x26a;
      }
      break;
    case 0x25d:
    case 0x26a:
    case 0x273:
    case 0x27e:
      local_fc = FLOAT_803df964;
      local_130 = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25d) {
        local_f6 = 0x7a;
      }
      else if (param_2 == 0x273) {
        local_f6 = 0x202;
      }
      else if (param_2 == 0x27e) {
        local_f6 = 0x7a;
      }
      else {
        local_f6 = 0x1fe;
      }
      break;
    case 0x25e:
    case 0x26b:
    case 0x27b:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df8b4 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df8fc * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(10,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df958 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df8ec * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe,0x12);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df95c * (float)(local_38 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df968;
      local_130 = FUN_800221a0(0x28,0x50);
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25e) {
        local_f6 = 0x79;
        local_134 = 0x25d;
      }
      else if (param_2 == 0x27b) {
        local_f6 = 0x1fb;
        local_134 = 0x27c;
      }
      else if (param_2 == 0x274) {
        local_f6 = 0x202;
        local_134 = 0x275;
      }
      else {
        local_f6 = 0x1ff;
        local_134 = 0x26c;
      }
      break;
    case 0x25f:
    case 0x26c:
    case 0x275:
    case 0x27c:
      local_fc = FLOAT_803df968;
      local_130 = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25f) {
        local_f6 = 0x79;
      }
      else if (param_2 == 0x275) {
        local_f6 = 0x202;
      }
      else if (param_2 == 0x27c) {
        local_f6 = 0x1fb;
      }
      else {
        local_f6 = 0x1ff;
      }
      break;
    case 0x260:
    case 0x261:
    case 0x262:
    case 0x278:
      uVar2 = FUN_800221a0(0xffffffda,0x26);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(10,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff94,0x6c);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffffd,3);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df8ec * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffffa,6);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df95c * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffffd,3);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df95c * (float)(local_40 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df96c;
      local_130 = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x80480110;
      if (param_2 == 0x278) {
        local_f6 = (short)DAT_8031066c;
      }
      else {
        local_f6 = (short)(&PTR_LAB_8030fce0)[param_2];
      }
      break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
      uVar2 = FUN_800221a0(0xfffffff8,8);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff8,8);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffffd,3);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803df904 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_fc = FLOAT_803df96c;
      local_130 = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x480110;
      if (param_2 == 0x276) {
        local_f6 = (short)DAT_8031066c;
      }
      else {
        local_f6 = (short)(&PTR_FUN_8030fcd4)[param_2];
      }
      break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
      uVar2 = FUN_800221a0(0xfffffff8,8);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff8,8);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffffd,3);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803df904 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_fc = FLOAT_803df96c;
      local_130 = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x480100;
      if (param_2 == 0x277) {
        local_f6 = (short)DAT_8031066c;
      }
      else {
        local_f6 = (short)(&PTR_FUN_8030fcc8)[param_2];
      }
      break;
    case 0x26d:
      uVar2 = FUN_800221a0(0xffffffc4,0x3c);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffc4,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffee,0x12);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0x28,0x50);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803df970 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_fc = FLOAT_803df974;
      local_130 = 200;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x2000200;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x26e:
      local_fc = FLOAT_803df974;
      local_130 = 0x55;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x2000200;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x26f:
      uVar2 = FUN_800221a0(0x28,0x50);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df95c * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df978;
      local_130 = 0x7d;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x80200;
      local_f6 = 0x125;
      break;
    case 0x270:
      uVar2 = FUN_800221a0(0,5);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df97c;
      local_130 = 0x46;
      local_d8 = 0xff;
      local_f4 = (code *)0x810020c;
      local_f6 = 0x167;
      break;
    case 0x271:
      uVar2 = FUN_800221a0(0x28,0x50);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df95c * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df980;
      local_130 = 0x46;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100204;
      local_f0 = 0x800;
      local_f6 = 0x167;
      break;
    case 0x27f:
      local_fc = FLOAT_803df988 * *(float *)(param_1 + 8);
      local_130 = 0x28;
      local_d8 = 0x9b;
      local_f4 = (code *)0x80080208;
      local_f6 = 0x5f;
      local_e0 = 0x6400;
      local_de = 0x3200;
      local_dc = 0xa000;
      local_ec = 500;
      local_e8 = 0;
      local_e4 = 1000;
      local_f0 = 0x20;
      break;
    case 0x280:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_800221a0(0xffffffec,0x14);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803df9c0);
        local_104 = FLOAT_803df98c;
        uVar2 = FUN_800221a0(0xffffffec,0x14);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_20 - DOUBLE_803df9c0);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = FLOAT_803df98c + *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df95c * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8fc * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df95c * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803df994 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0) +
                 FLOAT_803df990;
      local_130 = FUN_800221a0(0xbe,0xfa);
      local_d8 = 0x9b;
      local_134 = 0x281;
      local_f4 = (code *)0x81488000;
      local_f6 = FUN_800221a0(0,2);
      local_f6 = local_f6 + 0x208;
      break;
    case 0x281:
      uVar2 = FUN_800221a0(2,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df998 * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df99c;
      local_130 = FUN_800221a0(0,0x1e);
      local_130 = local_130 + 10;
      local_d8 = 0xff;
      local_f4 = (code *)0x180200;
      local_f6 = 0x5f;
      local_e0 = 0x5000;
      local_de = 0x1e00;
      local_dc = 0x7800;
      local_ec = 0x5000;
      local_e8 = 0x1e00;
      local_e4 = 0x7800;
      local_f0 = 0x20;
      break;
    case 0x282:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_800221a0(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803df9c0);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(0xffffffe2,0x1e);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df95c * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(10,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df970 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(4,4);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df95c * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803df900 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0) +
                 FLOAT_803df9a0;
      local_130 = FUN_800221a0(0xe6,0x118);
      local_d8 = 0xff;
      local_134 = 0x284;
      local_f4 = (code *)0x81488200;
      local_f6 = 0xc0a;
      break;
    case 0x283:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_800221a0(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803df9c0);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(10,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df960 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df900 * (float)(local_20 - DOUBLE_803df9c0) + FLOAT_803df9a0;
      local_130 = FUN_800221a0(0xe6,0x118);
      local_d8 = 0x9b;
      local_f4 = (code *)0x80480200;
      local_f6 = 0xc0d;
      break;
    case 0x284:
      uVar2 = FUN_800221a0(2,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df998 * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df9a4;
      local_130 = 0x1e;
      local_d8 = 0x9b;
      local_f4 = (code *)0x180200;
      local_f6 = 0x5f;
      local_e0 = 0xff00;
      local_de = 0xff00;
      local_dc = 0x9b00;
      local_ec = 0x9600;
      local_e8 = 0x1400;
      local_e4 = 0x1400;
      local_f0 = 0x20;
      break;
    case 0x285:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_800221a0(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803df9c0);
        uVar2 = FUN_800221a0(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803df9c0);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_800221a0(2,4);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df998 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(2,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8d0 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df870 * (float)(local_28 - DOUBLE_803df9c0) + FLOAT_803df9a8;
      local_130 = FUN_800221a0(0,0x32);
      local_130 = local_130 + 0x32;
      local_d8 = 0x9b;
      local_f4 = (code *)0x180200;
      local_f6 = 0xc0a;
      break;
    case 0x286:
    case 0x287:
    case 0x288:
      uVar2 = FUN_800221a0(0xfffffffa,2);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df96c * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df96c * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df984;
      local_130 = 0x50;
      local_d8 = 0xff;
      local_f4 = (code *)0x80480208;
      if (param_2 == 0x286) {
        local_f6 = 0x160;
      }
      else if (param_2 == 0x287) {
        local_f6 = 0x200;
      }
      else if (param_2 == 0x288) {
        local_f6 = 0xdd;
      }
      break;
    case 0x289:
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df8b4 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df8b4 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x28,0x3c);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df95c * (float)(local_28 - DOUBLE_803df9c0) + FLOAT_803df880;
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803df93c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_130 = FUN_800221a0(0x14,0x8c);
      local_f4 = (code *)0x80400209;
      local_d7 = 0;
      local_f6 = 0x23b;
      break;
    case 0x28a:
      local_100 = FLOAT_803df9b0;
      local_fc = FLOAT_803df904;
      local_d8 = 0x55;
      local_130 = FUN_800221a0(0x32,0x40);
      local_f4 = (code *)0x200;
      local_f6 = 0xc9d;
      break;
    case 0x28b:
      uVar2 = FUN_800221a0(0,300);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df978;
      local_130 = 0x14;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100200;
      local_f6 = 0x159;
      break;
    case 0x28c:
      uVar2 = FUN_800221a0(0xffffffce,0x32);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,200);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffce,0x32);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df870 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df870 * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x32,100);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df9b4 * (float)(local_40 - DOUBLE_803df9c0);
      local_130 = FUN_800221a0(0,0x1e);
      local_130 = local_130 + 100;
      local_d8 = 0xff;
      local_f4 = (code *)0x88108;
      local_f6 = 0x159;
      break;
    case 0x28d:
      uVar2 = FUN_800221a0(0x5a,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df93c * (float)(local_18 - DOUBLE_803df9c0);
      local_130 = FUN_800221a0(0,0x14);
      local_130 = local_130 + 10;
      local_d8 = 0x7d;
      local_f4 = (code *)0x500200;
      local_f6 = 0x159;
      break;
    case 0x28e:
      uVar2 = FUN_800221a0(0xfffffc18,1000);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(300,0x708);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffc18,1000);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xffffffd8,0x28);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803db7c8 *
                  FLOAT_803df970 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = -FLOAT_803db7c8 * FLOAT_803df970 * (float)(local_38 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df96c;
      local_130 = 0x118;
      local_d8 = 0xff;
      local_f0 = 0x300020;
      local_f4 = (code *)0x2008000;
      local_e0 = 0xffff;
      local_de = 0xffff;
      local_dc = 0xffff;
      local_ec = 0x63bf;
      local_e8 = 0x9e7;
      local_e4 = 1000;
      local_f6 = 0x23b;
      break;
    case 0x28f:
    case 0x290:
    case 0x291:
    case 0x292:
      uVar2 = FUN_800221a0(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,100);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffe70,400);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(5,0x19);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803df93c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_130 = 0x230;
      local_d8 = 0xff;
      local_12c = FUN_800221a0(0,0xffff);
      local_12a = FUN_800221a0(0,0xffff);
      local_12c = FUN_800221a0(0,0xffff);
      uVar2 = FUN_800221a0(0xe6,800);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_120 = (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe6,800);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_40 - DOUBLE_803df9c0);
      uStack68 = FUN_800221a0(0xe6,800);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_118 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_f0 = 0x20;
      local_f4 = (code *)0x86000008;
      sVar4 = FUN_800221a0(0,40000);
      local_e0 = sVar4 + 0x63bf;
      sVar4 = FUN_800221a0(0,40000);
      local_de = sVar4 + 0x3caf;
      iVar3 = FUN_800221a0(0,10000);
      local_e4 = iVar3 + 0x159fU & 0xffff;
      local_dc = (undefined2)local_e4;
      local_ec = (uint)local_e0;
      local_e8 = (uint)local_de;
      local_f6 = (short)param_2 + 0x113;
      break;
    case 0x293:
    case 0x294:
    case 0x295:
    case 0x296:
      uVar2 = FUN_800221a0(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      local_104 = FLOAT_803df9b8;
      uVar2 = FUN_800221a0(0xfffffe70,400);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df9bc * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(100,200);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803df870 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0x28);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df9bc * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(5,0x19);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df93c * (float)(local_40 - DOUBLE_803df9c0);
      local_130 = 2000;
      local_d8 = 0xff;
      local_12c = FUN_800221a0(0,0xffff);
      local_12a = FUN_800221a0(0,0xffff);
      local_12c = FUN_800221a0(0,0xffff);
      uStack68 = FUN_800221a0(0xe6,800);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_120 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe6,800);
      local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_50 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_118 = (float)(local_58 - DOUBLE_803df9c0);
      local_f0 = 0x31000020;
      local_f4 = (code *)0x8e000108;
      iVar3 = (param_2 + -0x292) * 10000;
      sVar4 = FUN_800221a0(0,iVar3);
      local_e0 = sVar4 + 0x63bf;
      sVar4 = FUN_800221a0(0,iVar3);
      local_de = sVar4 + 0x3caf;
      iVar3 = FUN_800221a0(0,10000);
      local_e4 = iVar3 + 0x159fU & 0xffff;
      local_dc = (undefined2)local_e4;
      local_ec = (uint)local_e0;
      local_e8 = (uint)local_de;
      local_f6 = (short)param_2 + 0x10f;
      break;
    case 0x297:
      uVar2 = FUN_800221a0(0xfffffff0,0x10);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df944 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(5,0x10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df948 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff0,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df94c * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df950;
      local_130 = 0x54;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x29d:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      local_12c = 1000;
      local_12a = 1000;
      local_128 = 1000;
      local_120 = FLOAT_803df884;
      local_11c = FLOAT_803df884;
      local_118 = FLOAT_803df884;
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_130 = 6;
      local_d8 = 0xe1;
      local_f4 = (code *)0x4a0010;
      iVar3 = FUN_800221a0(0,1);
      if (iVar3 == 0) {
        local_f0 = 0x102;
      }
      else {
        local_f0 = 0x202;
      }
      if (FLOAT_803df884 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_800221a0(0,3);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df87c * (float)(local_18 - DOUBLE_803df9c0) + FLOAT_803df870;
        local_f6 = 0xc0f;
      }
      else {
        uVar2 = FUN_800221a0(0,3);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df87c * (float)(local_18 - DOUBLE_803df9c0) + FLOAT_803df924;
        local_f6 = 0xc0f;
      }
      break;
    case 0x29e:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_130 = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x480010;
      if (FLOAT_803df884 == *(float *)(param_3 + 4)) {
        local_fc = FLOAT_803df928;
      }
      else {
        local_fc = FLOAT_803df92c;
      }
      local_f6 = 0x74;
      local_f0 = 2;
      break;
    case 0x29f:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_130 = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x480010;
      local_f0 = 2;
      if (FLOAT_803df884 == *(float *)(param_3 + 4)) {
        local_fc = FLOAT_803df8c8;
        local_f6 = 0xc22;
      }
      else {
        local_fc = FLOAT_803df930;
        local_f6 = 0xdc;
      }
      break;
    case 0x2a0:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      local_130 = 0x1e;
      local_d7 = 0;
      local_d8 = 0x37;
      local_f4 = (code *)0x180010;
      if (FLOAT_803df884 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_800221a0(0x14,0x32);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df934 * (float)(local_18 - DOUBLE_803df9c0);
        local_f6 = 0x73;
      }
      else {
        uVar2 = FUN_800221a0(0x14,0x32);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df938 * (float)(local_18 - DOUBLE_803df9c0);
        local_f6 = 0x73;
      }
      break;
    case 0x2a1:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c344 = FLOAT_803df884;
        DAT_8039c348 = FLOAT_803df884;
        DAT_8039c34c = FLOAT_803df884;
        DAT_8039c340 = FLOAT_803df878;
        DAT_8039c338 = 0;
        DAT_8039c33a = 0;
        DAT_8039c33c = 0;
        param_3 = &DAT_8039c338;
      }
      local_130 = 0x3c;
      local_d7 = 0;
      local_d8 = 0x37;
      local_f4 = (code *)0x480010;
      local_f0 = 2;
      if (FLOAT_803df884 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_800221a0(0x46,0x50);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df93c * (float)(local_18 - DOUBLE_803df9c0);
        local_f6 = 0x73;
      }
      else {
        uVar2 = FUN_800221a0(0x46,0x50);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803df940 * (float)(local_18 - DOUBLE_803df9c0);
        local_f6 = 0x73;
      }
      break;
    case 0x2a2:
      uVar2 = FUN_800221a0(0xffffff38,200);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      local_104 = FLOAT_803df914;
      uVar2 = FUN_800221a0(0xfffffd44,700);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xc,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df918 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xc,0x10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803df91c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_fc = FLOAT_803df920;
      local_130 = 0x82;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0xc9d;
      break;
    case 0x2a3:
      uVar2 = FUN_800221a0(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff38,200);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x46,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df910 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(1,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803df8f4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_130 = 0x32;
      local_d8 = 0x2d;
      local_f4 = (code *)0x100;
      local_f6 = 0x16c;
      break;
    case 0x2a4:
      uVar2 = FUN_800221a0(0xffffffa6,0x5a);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,100);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffd44,700);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffffe,2);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df904 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(2,5);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df908 * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffffe,2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df90c * (float)(local_40 - DOUBLE_803df9c0);
      uStack68 = FUN_800221a0(0x50,200);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803df87c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_130 = 0x50;
      local_f4 = (code *)0x180208;
      local_f0 = 0x1000000;
      local_f6 = 0x5f;
      break;
    case 0x2a5:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff88,0x78);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df874 * (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffffe,2);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803df8bc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(2,5);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8fc * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffffe,2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8bc * (float)(local_40 - DOUBLE_803df9c0);
      uStack68 = FUN_800221a0(0x50,0x78);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803df900 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_130 = 0x50;
      local_f4 = (code *)0x180208;
      local_f0 = 0x1000000;
      local_f6 = 0x5f;
      break;
    case 0x2a6:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffc4,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df870 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(7,10);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8e8 * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0xffffffe2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8f4 * (float)(local_40 - DOUBLE_803df9c0);
      uStack68 = FUN_800221a0(100,0x78);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803df8f8 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_130 = 0x3b6;
      local_d8 = 0xff;
      local_f4 = FUN_80080100;
      local_f6 = 0x5c;
      break;
    case 0x2a7:
      uVar2 = FUN_800221a0(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffc4,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803df9c0);
      uStack44 = FUN_800221a0(0xfffffff6,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803df870 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(7,10);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8e8 * (float)(local_38 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffffd8,0xffffffe2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8ec * (float)(local_40 - DOUBLE_803df9c0);
      uStack68 = FUN_800221a0(5,0x19);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803df8f0 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_130 = FUN_800221a0(0x186,0x1c2);
      local_d8 = 0xff;
      local_12c = FUN_800221a0(0,0xffff);
      local_12a = FUN_800221a0(0,0xffff);
      local_12c = FUN_800221a0(0,0xffff);
      uVar2 = FUN_800221a0(0xe6,800);
      local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_120 = (float)(local_50 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_58 - DOUBLE_803df9c0);
      uStack92 = FUN_800221a0(0xe6,800);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_118 = (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df9c0);
      iVar3 = FUN_800221a0(0,40000);
      local_ec = iVar3 + 0x63bfU & 0xffff;
      local_e0 = (ushort)local_ec;
      iVar3 = FUN_800221a0(0,40000);
      local_e8 = iVar3 + 0x3cafU & 0xffff;
      local_de = (ushort)local_e8;
      iVar3 = FUN_800221a0(0,10000);
      local_e4 = iVar3 + 0x159fU & 0xffff;
      local_dc = (undefined2)local_e4;
      local_f0 = 0x1000020;
      local_f4 = (code *)0x86000000;
      local_f6 = 0x3a2;
      break;
    case 0x2a8:
      uVar2 = FUN_800221a0(0xfffffff0,0x10);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df8d8 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(5,0x10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8dc * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xfffffff0,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8e0 * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8e4;
      local_130 = 0x12;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0x201;
      break;
    case 0x2a9:
      uVar2 = FUN_800221a0(0,500);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8d4;
      local_130 = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100200;
      local_f6 = 0x26d;
      break;
    case 0x2aa:
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df870 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(100,0x96);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8d0 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df870 * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8cc;
      local_130 = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)&DAT_80000200;
      local_f0 = 0x200000;
      local_f6 = 0x23b;
      break;
    case 0x2ab:
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df870 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(100,0x96);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8c8 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df870 * (float)(local_28 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8cc;
      local_130 = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)&DAT_80000200;
      local_f0 = 0x200000;
      local_f6 = 0x23b;
      break;
    case 0x2ac:
      uVar2 = FUN_800221a0(1000,0x640);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x28,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8c4 * (float)(local_20 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8c0;
      local_130 = 0x82;
      local_d8 = 0x9b;
      local_f4 = (code *)0x400100;
      local_f6 = 0xc0e;
      break;
    case 0x2ad:
      uVar2 = FUN_800221a0(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803df874 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x28,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8bc * (float)(local_20 - DOUBLE_803df9c0);
      local_fc = FLOAT_803df8c0;
      local_130 = 0x82;
      local_d8 = 0xff;
      local_f4 = (code *)0x400200;
      local_f0 = 0x100;
      local_f6 = 0x156;
      break;
    case 0x2ae:
      local_104 = FLOAT_803df8b8;
      local_fc = FLOAT_803df8b4;
      local_130 = 0x30;
      local_d7 = 0;
      local_f4 = (code *)0x8100210;
      local_f0 = 0x2000000;
      local_f6 = 0x205;
      break;
    case 0x2af:
      local_fc = FLOAT_803df8b4;
      local_130 = 0x30;
      local_d7 = 0;
      iVar3 = FUN_800221a0(0,1);
      if (iVar3 == 0) {
        local_f4 = (code *)0x180210;
      }
      else {
        local_f4 = (code *)0x8100210;
      }
      local_f0 = 0x2000000;
      local_f6 = 0x205;
      break;
    case 0x2b0:
      uStack204 = FUN_800221a0(0xffffff84,0x7c);
      uStack204 = uStack204 ^ 0x80000000;
      local_d0 = 0x43300000;
      local_114 = FLOAT_803df888 * (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803df9c0)
      ;
      uVar2 = FUN_800221a0(0x392,0x4d6);
      local_c8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df88c * (float)(local_c8 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff84,0x7c);
      local_c0 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df890 * (float)(local_c0 - DOUBLE_803df9c0);
      uStack180 = FUN_800221a0(0xfffffe30,0x1d0);
      uStack180 = uStack180 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_108 = FLOAT_803df894 * (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803df9c0)
      ;
      local_104 = FLOAT_803df884;
      uVar2 = FUN_800221a0(0xfffffe38,0x1c8);
      local_b0 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803df898 * (float)(local_b0 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x1d,0x21);
      local_a8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df89c * (float)(local_a8 - DOUBLE_803df9c0);
      local_130 = 0x13f;
      local_f6 = 0x26d;
      local_f4 = (code *)0x400100;
      break;
    case 0x2b1:
      local_a8 = (double)(longlong)(int)DAT_80310564;
      local_b0 = (double)(longlong)(int)DAT_80310568;
      uStack180 = FUN_800221a0((int)DAT_80310564,(int)DAT_80310568);
      uStack180 = uStack180 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_114 = DAT_80310560 * (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803df9c0);
      local_c0 = (double)(longlong)(int)DAT_80310570;
      local_c8 = (double)(longlong)(int)DAT_80310574;
      uStack204 = FUN_800221a0((int)DAT_80310570,(int)DAT_80310574);
      uStack204 = uStack204 ^ 0x80000000;
      local_d0 = 0x43300000;
      local_110 = DAT_8031056c * (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803df9c0);
      local_a0 = (longlong)(int)DAT_8031057c;
      local_98 = (longlong)(int)DAT_80310580;
      uStack140 = FUN_800221a0((int)DAT_8031057c,(int)DAT_80310580);
      uStack140 = uStack140 ^ 0x80000000;
      local_90 = 0x43300000;
      local_10c = DAT_80310578 * (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803df9c0);
      local_88 = (longlong)(int)DAT_80310588;
      local_80 = (longlong)(int)DAT_8031058c;
      uStack116 = FUN_800221a0((int)DAT_80310588,(int)DAT_8031058c);
      uStack116 = uStack116 ^ 0x80000000;
      local_78 = 0x43300000;
      local_108 = DAT_80310584 * (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803df9c0);
      local_70 = (longlong)(int)DAT_80310594;
      local_68 = (longlong)(int)DAT_80310598;
      uStack92 = FUN_800221a0((int)DAT_80310594,(int)DAT_80310598);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_104 = DAT_80310590 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803df9c0);
      local_58 = (double)(longlong)(int)DAT_803105a0;
      local_50 = (double)(longlong)(int)DAT_803105a4;
      uStack68 = FUN_800221a0((int)DAT_803105a0,(int)DAT_803105a4);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_100 = DAT_8031059c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803df9c0);
      local_40 = (double)(longlong)(int)DAT_803105ac;
      local_38 = (double)(longlong)(int)DAT_803105b0;
      uStack44 = FUN_800221a0((int)DAT_803105ac,(int)DAT_803105b0);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = DAT_803105a8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      local_28 = (double)(longlong)(int)DAT_803105b8;
      local_20 = (double)(longlong)(int)DAT_803105bc;
      local_130 = FUN_800221a0((int)DAT_803105b8,(int)DAT_803105bc);
      local_130 = (int)DAT_803105b4 + local_130;
      local_e0 = DAT_803105f4;
      local_de = DAT_803105f6;
      local_dc = DAT_803105f8;
      local_ec = (uint)DAT_803105fa;
      local_e8 = (uint)DAT_803105fc;
      local_e4 = (uint)DAT_803105fe;
      if (DAT_803105c4 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105c4 + -1);
      }
      if (DAT_803105c8 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105c8 + -1);
      }
      if (DAT_803105cc != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105cc + -1);
      }
      if (DAT_803105d0 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105d0 + -1);
      }
      if (DAT_803105d4 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105d4 + -1);
      }
      if (DAT_803105d8 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_803105d8 + -1);
      }
      local_f0 = 0x2000000;
      if (DAT_803105dc != 0) {
        local_f0 = 1 << DAT_803105dc + -1 | 0x2000000;
      }
      if (DAT_803105e0 != 0) {
        local_f0 = local_f0 | 1 << DAT_803105e0 + -1;
      }
      if (DAT_803105e4 != 0) {
        local_f0 = local_f0 | 1 << DAT_803105e4 + -1;
      }
      if (DAT_803105e8 != 0) {
        local_f0 = local_f0 | 1 << DAT_803105e8 + -1;
      }
      if (DAT_803105ec != 0) {
        local_f0 = local_f0 | 1 << DAT_803105ec + -1;
      }
      if (DAT_803105f0 != 0) {
        local_f0 = local_f0 | 1 << DAT_803105f0 + -1;
      }
      local_18 = (double)(longlong)(int)DAT_803105c0;
      local_f6 = (short)(int)DAT_803105c0;
      local_d8 = FUN_800221a0(DAT_80310600,DAT_80310601);
      break;
    case 0x2b2:
      uVar2 = FUN_800221a0(0xfffffed8,0xf9);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803df8a0 * (float)(local_18 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0x150,0x2de);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803df8a4 * (float)(local_20 - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(0xffffff04,0xf9);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803df8a8 * (float)(local_28 - DOUBLE_803df9c0);
      FUN_800221a0(0,0);
      local_108 = FLOAT_803df884;
      FUN_800221a0(1,1);
      local_104 = FLOAT_803df884;
      uStack44 = FUN_800221a0(0,0);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_100 = FLOAT_803df8ac * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803df9c0);
      uVar2 = FUN_800221a0(10,0x30);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803df8b0 * (float)(local_38 - DOUBLE_803df9c0);
      local_130 = FUN_800221a0(1,0x26);
      local_130 = local_130 + 0xe;
      local_f6 = 0x1f;
      local_f4 = (code *)0x1000200;
    }
    local_f4 = (code *)((uint)local_f4 | param_4);
    if ((((uint)local_f4 & 1) != 0) && (((uint)local_f4 & 2) != 0)) {
      local_f4 = (code *)((uint)local_f4 ^ 2);
    }
    if (((uint)local_f4 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_138 != 0) {
          local_108 = local_108 + *(float *)(local_138 + 0x18);
          local_104 = local_104 + *(float *)(local_138 + 0x1c);
          local_100 = local_100 + *(float *)(local_138 + 0x20);
        }
      }
      else {
        local_108 = local_108 + local_120;
        local_104 = local_104 + local_11c;
        local_100 = local_100 + local_118;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_138,0xffffffff,param_2,0);
    DAT_803dd348 = DAT_803dd2c4;
  }
  return uVar1;
}

