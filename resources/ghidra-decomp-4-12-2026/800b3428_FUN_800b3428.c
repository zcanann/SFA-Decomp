// Function: FUN_800b3428
// Entry: 800b3428
// Size: 15400 bytes

undefined4 FUN_800b3428(int param_1,int param_2,undefined2 *param_3,uint param_4,undefined param_5)

{
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  int local_138 [3];
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
  uint uStack_cc;
  undefined8 local_c8;
  undefined8 local_c0;
  undefined4 local_b8;
  uint uStack_b4;
  undefined8 local_b0;
  undefined8 local_a8;
  longlong local_a0;
  longlong local_98;
  undefined4 local_90;
  uint uStack_8c;
  longlong local_88;
  longlong local_80;
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  longlong local_68;
  undefined4 local_60;
  uint uStack_5c;
  undefined8 local_58;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined8 local_40;
  undefined8 local_38;
  undefined4 local_30;
  uint uStack_2c;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  
  FLOAT_803dc420 = FLOAT_803dc420 + FLOAT_803e04f0;
  if (FLOAT_803e04f8 < FLOAT_803dc420) {
    FLOAT_803dc420 = FLOAT_803e04f4;
  }
  FLOAT_803dc424 = FLOAT_803dc424 + FLOAT_803e04fc;
  if (FLOAT_803e04f8 < FLOAT_803dc424) {
    FLOAT_803dc424 = FLOAT_803e0500;
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
    local_108 = FLOAT_803e0504;
    local_104 = FLOAT_803e0504;
    local_100 = FLOAT_803e0504;
    local_114 = FLOAT_803e0504;
    local_110 = FLOAT_803e0504;
    local_10c = FLOAT_803e0504;
    local_fc = FLOAT_803e0504;
    local_138[2] = 0;
    local_138[1] = 0xffffffff;
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
    local_138[0] = param_1;
    switch(param_2) {
    case 600:
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e0618 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0618 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0618 * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e062c;
      local_138[2] = FUN_80022264(0x50,0x82);
      local_d8 = 0x9b;
      local_f4 = (code *)0x180200;
      local_f6 = 0x7b;
      break;
    default:
      return 0xffffffff;
    case 0x25b:
      local_fc = FLOAT_803e05d4;
      local_138[2] = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      local_f6 = 0x7b;
      break;
    case 0x25c:
    case 0x269:
    case 0x27d:
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e0534 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e057c * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(10,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05d8 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e05dc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xe,0x12);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05e0 * (float)(local_38 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05e4;
      local_138[2] = FUN_80022264(0x28,0x50);
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25c) {
        local_f6 = 0x7a;
        local_138[1] = 0x25d;
      }
      else if (param_2 == 0x272) {
        local_f6 = 0x202;
        local_138[1] = 0x273;
      }
      else if (param_2 == 0x27d) {
        local_f6 = 0x7a;
        local_138[1] = 0x27e;
      }
      else {
        local_f6 = 0x1fe;
        local_138[1] = 0x26a;
      }
      break;
    case 0x25d:
    case 0x26a:
    case 0x273:
    case 0x27e:
      local_fc = FLOAT_803e05e4;
      local_138[2] = 0x3c;
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
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e0534 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e057c * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(10,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05d8 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e056c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xe,0x12);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05dc * (float)(local_38 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05e8;
      local_138[2] = FUN_80022264(0x28,0x50);
      local_d8 = 0xff;
      local_f4 = (code *)0x2000104;
      local_f0 = 0x400;
      if (param_2 == 0x25e) {
        local_f6 = 0x79;
        local_138[1] = 0x25d;
      }
      else if (param_2 == 0x27b) {
        local_f6 = 0x1fb;
        local_138[1] = 0x27c;
      }
      else if (param_2 == 0x274) {
        local_f6 = 0x202;
        local_138[1] = 0x275;
      }
      else {
        local_f6 = 0x1ff;
        local_138[1] = 0x26c;
      }
      break;
    case 0x25f:
    case 0x26c:
    case 0x275:
    case 0x27c:
      local_fc = FLOAT_803e05e8;
      local_138[2] = 0x3c;
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
      uVar2 = FUN_80022264(0xffffffda,0x26);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(10,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff94,0x6c);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffffd,3);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e056c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xfffffffa,6);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05dc * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffffd,3);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05dc * (float)(local_40 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05ec;
      local_138[2] = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x80480110;
      if (param_2 == 0x278) {
        local_f6 = (short)DAT_8031122c;
      }
      else {
        local_f6 = (short)(&PTR_LAB_803108a0)[param_2];
      }
      break;
    case 0x263:
    case 0x264:
    case 0x265:
    case 0x276:
      uVar2 = FUN_80022264(0xfffffff8,8);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff8,8);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffffd,3);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803e0584 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      local_fc = FLOAT_803e05ec;
      local_138[2] = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x480110;
      if (param_2 == 0x276) {
        local_f6 = (short)DAT_8031122c;
      }
      else {
        local_f6 = (short)(&PTR_FUN_80310894)[param_2];
      }
      break;
    case 0x266:
    case 0x267:
    case 0x268:
    case 0x277:
      uVar2 = FUN_80022264(0xfffffff8,8);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x50);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff8,8);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffffd,3);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803e0584 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      local_fc = FLOAT_803e05ec;
      local_138[2] = 100;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x480100;
      if (param_2 == 0x277) {
        local_f6 = (short)DAT_8031122c;
      }
      else {
        local_f6 = (short)(&PTR_FUN_80310888)[param_2];
      }
      break;
    case 0x26d:
      uVar2 = FUN_80022264(0xffffffc4,0x3c);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffc4,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffee,0x12);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0x28,0x50);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803e05f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      local_fc = FLOAT_803e05f4;
      local_138[2] = 200;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x2000200;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x26e:
      local_fc = FLOAT_803e05f4;
      local_138[2] = 0x55;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x2000200;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x26f:
      uVar2 = FUN_80022264(0x28,0x50);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05dc * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05f8;
      local_138[2] = 0x7d;
      local_d8 = 0xff;
      local_d7 = 0x10;
      local_f4 = (code *)0x80200;
      local_f6 = 0x125;
      break;
    case 0x270:
      uVar2 = FUN_80022264(0,5);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05fc;
      local_138[2] = 0x46;
      local_d8 = 0xff;
      local_f4 = (code *)0x810020c;
      local_f6 = 0x167;
      break;
    case 0x271:
      uVar2 = FUN_80022264(0x28,0x50);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05dc * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0600;
      local_138[2] = 0x46;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100204;
      local_f0 = 0x800;
      local_f6 = 0x167;
      break;
    case 0x27f:
      local_fc = FLOAT_803e0608 * *(float *)(param_1 + 8);
      local_138[2] = 0x28;
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
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_80022264(0xffffffec,0x14);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803e0640);
        local_104 = FLOAT_803e060c;
        uVar2 = FUN_80022264(0xffffffec,0x14);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_20 - DOUBLE_803e0640);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = FLOAT_803e060c + *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e05dc * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e057c * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05dc * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803e0614 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
                 + FLOAT_803e0610;
      local_138[2] = FUN_80022264(0xbe,0xfa);
      local_d8 = 0x9b;
      local_138[1] = 0x281;
      local_f4 = (code *)0x81488000;
      uVar2 = FUN_80022264(0,2);
      local_f6 = (short)uVar2 + 0x208;
      break;
    case 0x281:
      uVar2 = FUN_80022264(2,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0618 * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e061c;
      local_138[2] = FUN_80022264(0,0x1e);
      local_138[2] = local_138[2] + 10;
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
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_80022264(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803e0640);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(0xffffffe2,0x1e);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e05dc * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(10,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05f0 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(4,4);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05dc * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803e0580 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
                 + FLOAT_803e0620;
      local_138[2] = FUN_80022264(0xe6,0x118);
      local_d8 = 0xff;
      local_138[1] = 0x284;
      local_f4 = (code *)0x81488200;
      local_f6 = 0xc0a;
      break;
    case 0x283:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_80022264(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803e0640);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(10,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05e0 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e0580 * (float)(local_20 - DOUBLE_803e0640) + FLOAT_803e0620;
      local_138[2] = FUN_80022264(0xe6,0x118);
      local_d8 = 0x9b;
      local_f4 = (code *)0x80480200;
      local_f6 = 0xc0d;
      break;
    case 0x284:
      uVar2 = FUN_80022264(2,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0618 * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0624;
      local_138[2] = 0x1e;
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
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = FUN_80022264(0xfffffffb,5);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_108 = (float)(local_18 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(1,10);
        local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_104 = (float)(local_20 - DOUBLE_803e0640);
        uVar2 = FUN_80022264(0xffffff6a,0x96);
        local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_100 = (float)(local_28 - DOUBLE_803e0640);
      }
      else {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      uVar2 = FUN_80022264(2,4);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0618 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(2,4);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0550 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e04f0 * (float)(local_28 - DOUBLE_803e0640) + FLOAT_803e0628;
      local_138[2] = FUN_80022264(0,0x32);
      local_138[2] = local_138[2] + 0x32;
      local_d8 = 0x9b;
      local_f4 = (code *)0x180200;
      local_f6 = 0xc0a;
      break;
    case 0x286:
    case 0x287:
    case 0x288:
      uVar2 = FUN_80022264(0xfffffffa,2);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e05ec * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff6,10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05ec * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0604;
      local_138[2] = 0x50;
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
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e0534 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e0534 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x28,0x3c);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05dc * (float)(local_28 - DOUBLE_803e0640) + FLOAT_803e0500;
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803e05bc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640);
      local_138[2] = FUN_80022264(0x14,0x8c);
      local_f4 = (code *)0x80400209;
      local_d7 = 0;
      local_f6 = 0x23b;
      break;
    case 0x28a:
      local_100 = FLOAT_803e0630;
      local_fc = FLOAT_803e0584;
      local_d8 = 0x55;
      local_138[2] = FUN_80022264(0x32,0x40);
      local_f4 = (code *)0x200;
      local_f6 = 0xc9d;
      break;
    case 0x28b:
      uVar2 = FUN_80022264(0,300);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05f8;
      local_138[2] = 0x14;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100200;
      local_f6 = 0x159;
      break;
    case 0x28c:
      uVar2 = FUN_80022264(0xffffffce,0x32);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,200);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffce,0x32);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e04f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e04f0 * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x32,100);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e0634 * (float)(local_40 - DOUBLE_803e0640);
      local_138[2] = FUN_80022264(0,0x1e);
      local_138[2] = local_138[2] + 100;
      local_d8 = 0xff;
      local_f4 = (code *)0x88108;
      local_f6 = 0x159;
      break;
    case 0x28d:
      uVar2 = FUN_80022264(0x5a,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e05bc * (float)(local_18 - DOUBLE_803e0640);
      local_138[2] = FUN_80022264(0,0x14);
      local_138[2] = local_138[2] + 10;
      local_d8 = 0x7d;
      local_f4 = (code *)0x500200;
      local_f6 = 0x159;
      break;
    case 0x28e:
      uVar2 = FUN_80022264(0xfffffc18,1000);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(300,0x708);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffc18,1000);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xffffffd8,0x28);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803dc428 *
                  FLOAT_803e05f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = -FLOAT_803dc428 * FLOAT_803e05f0 * (float)(local_38 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05ec;
      local_138[2] = 0x118;
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
      uVar2 = FUN_80022264(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,100);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffe70,400);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(5,0x19);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803e05bc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640);
      local_138[2] = 0x230;
      local_d8 = 0xff;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12a = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uVar2 = FUN_80022264(0xe6,800);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_120 = (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xe6,800);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_40 - DOUBLE_803e0640);
      uStack_44 = FUN_80022264(0xe6,800);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_118 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_f0 = 0x20;
      local_f4 = (code *)0x86000008;
      uVar2 = FUN_80022264(0,40000);
      local_e0 = (short)uVar2 + 0x63bf;
      uVar2 = FUN_80022264(0,40000);
      local_de = (short)uVar2 + 0x3caf;
      uVar2 = FUN_80022264(0,10000);
      local_e4 = uVar2 + 0x159f & 0xffff;
      local_dc = (undefined2)(uVar2 + 0x159f);
      local_ec = (uint)local_e0;
      local_e8 = (uint)local_de;
      local_f6 = (short)param_2 + 0x113;
      break;
    case 0x293:
    case 0x294:
    case 0x295:
    case 0x296:
      uVar2 = FUN_80022264(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      local_104 = FLOAT_803e0638;
      uVar2 = FUN_80022264(0xfffffe70,400);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e063c * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(100,200);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_110 = FLOAT_803e04f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0xffffffd8,0x28);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e063c * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(5,0x19);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e05bc * (float)(local_40 - DOUBLE_803e0640);
      local_138[2] = 2000;
      local_d8 = 0xff;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12a = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uStack_44 = FUN_80022264(0xe6,800);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_120 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xe6,800);
      local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_50 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_118 = (float)(local_58 - DOUBLE_803e0640);
      local_f0 = 0x31000020;
      local_f4 = (code *)0x8e000108;
      uVar3 = (param_2 + -0x292) * 10000;
      uVar2 = FUN_80022264(0,uVar3);
      local_e0 = (short)uVar2 + 0x63bf;
      uVar2 = FUN_80022264(0,uVar3);
      local_de = (short)uVar2 + 0x3caf;
      uVar2 = FUN_80022264(0,10000);
      local_e4 = uVar2 + 0x159f & 0xffff;
      local_dc = (undefined2)(uVar2 + 0x159f);
      local_ec = (uint)local_e0;
      local_e8 = (uint)local_de;
      local_f6 = (short)param_2 + 0x10f;
      break;
    case 0x297:
      uVar2 = FUN_80022264(0xfffffff0,0x10);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e05c4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(5,0x10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e05c8 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff0,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e05cc * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e05d0;
      local_138[2] = 0x54;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0x1fe;
      break;
    case 0x29d:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      local_12c = 1000;
      local_12a = 1000;
      local_128 = 1000;
      local_120 = FLOAT_803e0504;
      local_11c = FLOAT_803e0504;
      local_118 = FLOAT_803e0504;
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_138[2] = 6;
      local_d8 = 0xe1;
      local_f4 = (code *)0x4a0010;
      uVar2 = FUN_80022264(0,1);
      if (uVar2 == 0) {
        local_f0 = 0x102;
      }
      else {
        local_f0 = 0x202;
      }
      if (FLOAT_803e0504 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_80022264(0,3);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e04fc * (float)(local_18 - DOUBLE_803e0640) + FLOAT_803e04f0;
        local_f6 = 0xc0f;
      }
      else {
        uVar2 = FUN_80022264(0,3);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e04fc * (float)(local_18 - DOUBLE_803e0640) + FLOAT_803e05a4;
        local_f6 = 0xc0f;
      }
      break;
    case 0x29e:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_138[2] = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x480010;
      if (FLOAT_803e0504 == *(float *)(param_3 + 4)) {
        local_fc = FLOAT_803e05a8;
      }
      else {
        local_fc = FLOAT_803e05ac;
      }
      local_f6 = 0x74;
      local_f0 = 2;
      break;
    case 0x29f:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_108 = *(float *)(param_3 + 6);
        local_104 = *(float *)(param_3 + 8);
        local_100 = *(float *)(param_3 + 10);
      }
      local_138[2] = 0x3c;
      local_d8 = 0xff;
      local_f4 = (code *)0x480010;
      local_f0 = 2;
      if (FLOAT_803e0504 == *(float *)(param_3 + 4)) {
        local_fc = FLOAT_803e0548;
        local_f6 = 0xc22;
      }
      else {
        local_fc = FLOAT_803e05b0;
        local_f6 = 0xdc;
      }
      break;
    case 0x2a0:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      local_138[2] = 0x1e;
      local_d7 = 0;
      local_d8 = 0x37;
      local_f4 = (code *)0x180010;
      if (FLOAT_803e0504 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_80022264(0x14,0x32);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e05b4 * (float)(local_18 - DOUBLE_803e0640);
        local_f6 = 0x73;
      }
      else {
        uVar2 = FUN_80022264(0x14,0x32);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e05b8 * (float)(local_18 - DOUBLE_803e0640);
        local_f6 = 0x73;
      }
      break;
    case 0x2a1:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfa4 = FLOAT_803e0504;
        DAT_8039cfa8 = FLOAT_803e0504;
        DAT_8039cfac = FLOAT_803e0504;
        DAT_8039cfa0 = FLOAT_803e04f8;
        DAT_8039cf98 = 0;
        DAT_8039cf9a = 0;
        DAT_8039cf9c = 0;
        param_3 = &DAT_8039cf98;
      }
      local_138[2] = 0x3c;
      local_d7 = 0;
      local_d8 = 0x37;
      local_f4 = (code *)0x480010;
      local_f0 = 2;
      if (FLOAT_803e0504 == *(float *)(param_3 + 4)) {
        uVar2 = FUN_80022264(0x46,0x50);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e05bc * (float)(local_18 - DOUBLE_803e0640);
        local_f6 = 0x73;
      }
      else {
        uVar2 = FUN_80022264(0x46,0x50);
        local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
        local_fc = FLOAT_803e05c0 * (float)(local_18 - DOUBLE_803e0640);
        local_f6 = 0x73;
      }
      break;
    case 0x2a2:
      uVar2 = FUN_80022264(0xffffff38,200);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      local_104 = FLOAT_803e0594;
      uVar2 = FUN_80022264(0xfffffd44,700);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xc,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0598 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xc,0x10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803e059c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      local_fc = FLOAT_803e05a0;
      local_138[2] = 0x82;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0xc9d;
      break;
    case 0x2a3:
      uVar2 = FUN_80022264(0xfffffe70,400);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff38,200);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x46,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0590 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(1,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = FLOAT_803e0574 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640);
      local_138[2] = 0x32;
      local_d8 = 0x2d;
      local_f4 = (code *)0x100;
      local_f6 = 0x16c;
      break;
    case 0x2a4:
      uVar2 = FUN_80022264(0xffffffa6,0x5a);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,100);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffd44,700);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffffe,2);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e0584 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(2,5);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0588 * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffffe,2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e058c * (float)(local_40 - DOUBLE_803e0640);
      uStack_44 = FUN_80022264(0x50,200);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803e04fc * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_138[2] = 0x50;
      local_f4 = (code *)0x180208;
      local_f0 = 0x1000000;
      local_f6 = 0x5f;
      break;
    case 0x2a5:
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff88,0x78);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e04f4 * (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffffe,2);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_10c = FLOAT_803e053c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(2,5);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e057c * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffffe,2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e053c * (float)(local_40 - DOUBLE_803e0640);
      uStack_44 = FUN_80022264(0x50,0x78);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803e0580 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_138[2] = 0x50;
      local_f4 = (code *)0x180208;
      local_f0 = 0x1000000;
      local_f6 = 0x5f;
      break;
    case 0x2a6:
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffc4,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e04f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(7,10);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0568 * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffd8,0xffffffe2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0574 * (float)(local_40 - DOUBLE_803e0640);
      uStack_44 = FUN_80022264(100,0x78);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803e0578 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_138[2] = 0x3b6;
      local_d8 = 0xff;
      local_f4 = FUN_80080100;
      local_f6 = 0x5c;
      break;
    case 0x2a7:
      uVar2 = FUN_80022264(0xffffffec,0x14);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,0x14);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffc4,0x14);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = (float)(local_28 - DOUBLE_803e0640);
      uStack_2c = FUN_80022264(0xfffffff6,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_114 = FLOAT_803e04f0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(7,10);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0568 * (float)(local_38 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffffd8,0xffffffe2);
      local_40 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e056c * (float)(local_40 - DOUBLE_803e0640);
      uStack_44 = FUN_80022264(5,0x19);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_fc = FLOAT_803e0570 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_138[2] = FUN_80022264(0x186,0x1c2);
      local_d8 = 0xff;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12a = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_12c = (undefined2)uVar2;
      uVar2 = FUN_80022264(0xe6,800);
      local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_120 = (float)(local_50 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xe6,800);
      local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_11c = (float)(local_58 - DOUBLE_803e0640);
      uStack_5c = FUN_80022264(0xe6,800);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_118 = (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0,40000);
      local_ec = uVar2 + 0x63bf & 0xffff;
      local_e0 = (ushort)(uVar2 + 0x63bf);
      uVar2 = FUN_80022264(0,40000);
      local_e8 = uVar2 + 0x3caf & 0xffff;
      local_de = (ushort)(uVar2 + 0x3caf);
      uVar2 = FUN_80022264(0,10000);
      local_e4 = uVar2 + 0x159f & 0xffff;
      local_dc = (undefined2)(uVar2 + 0x159f);
      local_f0 = 0x1000020;
      local_f4 = (code *)0x86000000;
      local_f6 = 0x3a2;
      break;
    case 0x2a8:
      uVar2 = FUN_80022264(0xfffffff0,0x10);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e0558 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(5,0x10);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e055c * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xfffffff0,0x10);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0560 * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0564;
      local_138[2] = 0x12;
      local_d8 = 0x9b;
      local_f4 = (code *)0x2000000;
      local_f0 = 0x200000;
      local_f6 = 0x201;
      break;
    case 0x2a9:
      uVar2 = FUN_80022264(0,500);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0554;
      local_138[2] = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)0x8100200;
      local_f6 = 0x26d;
      break;
    case 0x2aa:
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e04f0 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(100,0x96);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0550 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e04f0 * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e054c;
      local_138[2] = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)&DAT_80000200;
      local_f0 = 0x200000;
      local_f6 = 0x23b;
      break;
    case 0x2ab:
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e04f0 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(100,0x96);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0548 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e04f0 * (float)(local_28 - DOUBLE_803e0640);
      local_fc = FLOAT_803e054c;
      local_138[2] = 0x32;
      local_d8 = 0xff;
      local_f4 = (code *)&DAT_80000200;
      local_f0 = 0x200000;
      local_f6 = 0x23b;
      break;
    case 0x2ac:
      uVar2 = FUN_80022264(1000,0x640);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_104 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x28,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0544 * (float)(local_20 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0540;
      local_138[2] = 0x82;
      local_d8 = 0x9b;
      local_f4 = (code *)0x400100;
      local_f6 = 0xc0e;
      break;
    case 0x2ad:
      uVar2 = FUN_80022264(0xffffff9c,100);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_108 = FLOAT_803e04f4 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x28,0x3c);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e053c * (float)(local_20 - DOUBLE_803e0640);
      local_fc = FLOAT_803e0540;
      local_138[2] = 0x82;
      local_d8 = 0xff;
      local_f4 = (code *)0x400200;
      local_f0 = 0x100;
      local_f6 = 0x156;
      break;
    case 0x2ae:
      local_104 = FLOAT_803e0538;
      local_fc = FLOAT_803e0534;
      local_138[2] = 0x30;
      local_d7 = 0;
      local_f4 = (code *)0x8100210;
      local_f0 = 0x2000000;
      local_f6 = 0x205;
      break;
    case 0x2af:
      local_fc = FLOAT_803e0534;
      local_138[2] = 0x30;
      local_d7 = 0;
      uVar2 = FUN_80022264(0,1);
      if (uVar2 == 0) {
        local_f4 = (code *)0x180210;
      }
      else {
        local_f4 = (code *)0x8100210;
      }
      local_f0 = 0x2000000;
      local_f6 = 0x205;
      break;
    case 0x2b0:
      uStack_cc = FUN_80022264(0xffffff84,0x7c);
      uStack_cc = uStack_cc ^ 0x80000000;
      local_d0 = 0x43300000;
      local_114 = FLOAT_803e0508 * (float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(0x392,0x4d6);
      local_c8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e050c * (float)(local_c8 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff84,0x7c);
      local_c0 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0510 * (float)(local_c0 - DOUBLE_803e0640);
      uStack_b4 = FUN_80022264(0xfffffe30,0x1d0);
      uStack_b4 = uStack_b4 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_108 = FLOAT_803e0514 * (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e0640)
      ;
      local_104 = FLOAT_803e0504;
      uVar2 = FUN_80022264(0xfffffe38,0x1c8);
      local_b0 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_100 = FLOAT_803e0518 * (float)(local_b0 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x1d,0x21);
      local_a8 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e051c * (float)(local_a8 - DOUBLE_803e0640);
      local_138[2] = 0x13f;
      local_f6 = 0x26d;
      local_f4 = (code *)0x400100;
      break;
    case 0x2b1:
      local_a8 = (double)(longlong)(int)DAT_80311124;
      local_b0 = (double)(longlong)(int)DAT_80311128;
      uStack_b4 = FUN_80022264((int)DAT_80311124,(int)DAT_80311128);
      uStack_b4 = uStack_b4 ^ 0x80000000;
      local_b8 = 0x43300000;
      local_114 = DAT_80311120 * (float)((double)CONCAT44(0x43300000,uStack_b4) - DOUBLE_803e0640);
      local_c0 = (double)(longlong)(int)DAT_80311130;
      local_c8 = (double)(longlong)(int)DAT_80311134;
      uStack_cc = FUN_80022264((int)DAT_80311130,(int)DAT_80311134);
      uStack_cc = uStack_cc ^ 0x80000000;
      local_d0 = 0x43300000;
      local_110 = DAT_8031112c * (float)((double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803e0640);
      local_a0 = (longlong)(int)DAT_8031113c;
      local_98 = (longlong)(int)DAT_80311140;
      uStack_8c = FUN_80022264((int)DAT_8031113c,(int)DAT_80311140);
      uStack_8c = uStack_8c ^ 0x80000000;
      local_90 = 0x43300000;
      local_10c = DAT_80311138 * (float)((double)CONCAT44(0x43300000,uStack_8c) - DOUBLE_803e0640);
      local_88 = (longlong)(int)DAT_80311148;
      local_80 = (longlong)(int)DAT_8031114c;
      uStack_74 = FUN_80022264((int)DAT_80311148,(int)DAT_8031114c);
      uStack_74 = uStack_74 ^ 0x80000000;
      local_78 = 0x43300000;
      local_108 = DAT_80311144 * (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e0640);
      local_70 = (longlong)(int)DAT_80311154;
      local_68 = (longlong)(int)DAT_80311158;
      uStack_5c = FUN_80022264((int)DAT_80311154,(int)DAT_80311158);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_104 = DAT_80311150 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0640);
      local_58 = (double)(longlong)(int)DAT_80311160;
      local_50 = (double)(longlong)(int)DAT_80311164;
      uStack_44 = FUN_80022264((int)DAT_80311160,(int)DAT_80311164);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_100 = DAT_8031115c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0640);
      local_40 = (double)(longlong)(int)DAT_8031116c;
      local_38 = (double)(longlong)(int)DAT_80311170;
      uStack_2c = FUN_80022264((int)DAT_8031116c,(int)DAT_80311170);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_fc = DAT_80311168 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640);
      local_28 = (double)(longlong)(int)DAT_80311178;
      local_20 = (double)(longlong)(int)DAT_8031117c;
      local_138[2] = FUN_80022264((int)DAT_80311178,(int)DAT_8031117c);
      local_138[2] = (int)DAT_80311174 + local_138[2];
      local_e0 = DAT_803111b4;
      local_de = DAT_803111b6;
      local_dc = DAT_803111b8;
      local_ec = (uint)DAT_803111ba;
      local_e8 = (uint)DAT_803111bc;
      local_e4 = (uint)DAT_803111be;
      if (DAT_80311184 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_80311184 + -1);
      }
      if (DAT_80311188 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_80311188 + -1);
      }
      if (DAT_8031118c != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_8031118c + -1);
      }
      if (DAT_80311190 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_80311190 + -1);
      }
      if (DAT_80311194 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_80311194 + -1);
      }
      if (DAT_80311198 != 0) {
        local_f4 = (code *)((uint)local_f4 | 1 << DAT_80311198 + -1);
      }
      local_f0 = 0x2000000;
      if (DAT_8031119c != 0) {
        local_f0 = 1 << DAT_8031119c + -1 | 0x2000000;
      }
      if (DAT_803111a0 != 0) {
        local_f0 = local_f0 | 1 << DAT_803111a0 + -1;
      }
      if (DAT_803111a4 != 0) {
        local_f0 = local_f0 | 1 << DAT_803111a4 + -1;
      }
      if (DAT_803111a8 != 0) {
        local_f0 = local_f0 | 1 << DAT_803111a8 + -1;
      }
      if (DAT_803111ac != 0) {
        local_f0 = local_f0 | 1 << DAT_803111ac + -1;
      }
      if (DAT_803111b0 != 0) {
        local_f0 = local_f0 | 1 << DAT_803111b0 + -1;
      }
      local_18 = (double)(longlong)(int)DAT_80311180;
      local_f6 = (short)(int)DAT_80311180;
      uVar2 = FUN_80022264((uint)DAT_803111c0,(uint)DAT_803111c1);
      local_d8 = (undefined)uVar2;
      break;
    case 0x2b2:
      uVar2 = FUN_80022264(0xfffffed8,0xf9);
      local_18 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_114 = FLOAT_803e0520 * (float)(local_18 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0x150,0x2de);
      local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_110 = FLOAT_803e0524 * (float)(local_20 - DOUBLE_803e0640);
      uVar2 = FUN_80022264(0xffffff04,0xf9);
      local_28 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_10c = FLOAT_803e0528 * (float)(local_28 - DOUBLE_803e0640);
      FUN_80022264(0,0);
      local_108 = FLOAT_803e0504;
      FUN_80022264(1,1);
      local_104 = FLOAT_803e0504;
      uStack_2c = FUN_80022264(0,0);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_100 = FLOAT_803e052c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0640)
      ;
      uVar2 = FUN_80022264(10,0x30);
      local_38 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
      local_fc = FLOAT_803e0530 * (float)(local_38 - DOUBLE_803e0640);
      local_138[2] = FUN_80022264(1,0x26);
      local_138[2] = local_138[2] + 0xe;
      local_f6 = 0x1f;
      local_f4 = (code *)0x1000200;
    }
    local_f4 = (code *)((uint)local_f4 | param_4);
    if ((((uint)local_f4 & 1) != 0) && (((uint)local_f4 & 2) != 0)) {
      local_f4 = (code *)((uint)local_f4 ^ 2);
    }
    if (((uint)local_f4 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_138[0] != 0) {
          local_108 = local_108 + *(float *)(local_138[0] + 0x18);
          local_104 = local_104 + *(float *)(local_138[0] + 0x1c);
          local_100 = local_100 + *(float *)(local_138[0] + 0x20);
        }
      }
      else {
        local_108 = local_108 + local_120;
        local_104 = local_104 + local_11c;
        local_100 = local_100 + local_118;
      }
    }
    uVar1 = (**(code **)(*DAT_803dd6f8 + 8))(local_138,0xffffffff,param_2,0);
    DAT_803ddfc8 = DAT_803ddf44;
  }
  return uVar1;
}

