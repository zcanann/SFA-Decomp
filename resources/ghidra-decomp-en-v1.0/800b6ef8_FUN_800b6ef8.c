// Function: FUN_800b6ef8
// Entry: 800b6ef8
// Size: 7796 bytes

/* WARNING: Removing unreachable block (ram,0x800b8d4c) */

void FUN_800b6ef8(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  float fVar2;
  short *psVar3;
  undefined4 uVar4;
  short sVar7;
  int iVar5;
  uint uVar6;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  short *local_d8;
  undefined4 local_d4;
  int local_d0;
  undefined2 local_cc;
  undefined2 local_ca;
  undefined2 local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  undefined2 local_98;
  undefined2 local_96;
  uint local_94;
  undefined4 local_90;
  uint local_8c;
  uint local_88;
  undefined4 local_84;
  ushort local_80;
  undefined2 local_7e;
  undefined2 local_7c;
  undefined local_7a;
  undefined local_78;
  char local_77;
  undefined local_76;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  double local_60;
  double local_58;
  double local_50;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860d8();
  psVar3 = (short *)((ulonglong)uVar11 >> 0x20);
  if (psVar3 == (short *)0x0) {
    uVar4 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar4 = 0xffffffff;
        goto LAB_800b8d4c;
      }
      local_c0 = *(float *)(param_3 + 6);
      local_bc = *(float *)(param_3 + 8);
      local_b8 = *(float *)(param_3 + 10);
      local_c4 = *(float *)(param_3 + 4);
      local_c8 = param_3[2];
      local_ca = param_3[1];
      local_cc = *param_3;
      local_76 = param_5;
    }
    local_94 = 0;
    local_90 = 0;
    local_7a = (undefined)uVar11;
    local_a8 = FLOAT_803df9d0;
    local_a4 = FLOAT_803df9d0;
    local_a0 = FLOAT_803df9d0;
    local_b4 = FLOAT_803df9d0;
    local_b0 = FLOAT_803df9d0;
    local_ac = FLOAT_803df9d0;
    local_9c = FLOAT_803df9d0;
    local_d0 = 0;
    local_d4 = 0xffffffff;
    local_78 = 0xff;
    local_77 = '\0';
    local_96 = 0;
    local_80 = 0xffff;
    local_7e = 0xffff;
    local_7c = 0xffff;
    local_8c = 0xffff;
    local_88 = 0xffff;
    local_84 = 0xffff;
    local_98 = 0;
    local_d8 = psVar3;
    switch((int)uVar11) {
    case 500:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      uStack108 = FUN_800221a0(0xffffffec,0xfffffff6);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      local_a8 = FLOAT_803df9d8 * (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803dfa80);
      uStack100 = FUN_800221a0(0xfffffff6,10);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a4 = FLOAT_803df9d8 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xfffffff6,0);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a0 = FLOAT_803df9d8 * (float)(local_60 - DOUBLE_803dfa80);
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = local_a8 + *(float *)(param_3 + 6);
        local_a4 = local_a4 + *(float *)(param_3 + 8);
        local_a0 = local_a0 + *(float *)(param_3 + 10);
      }
      uVar6 = FUN_800221a0(0xd,0x14);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9dc * (float)(local_60 - DOUBLE_803dfa80);
      local_d0 = 0x19;
      local_78 = 0xff;
      local_94 = 0x80200;
      local_90 = 0x4000800;
      local_96 = 0x184;
      local_77 = FUN_800221a0(0,0x14);
      local_77 = local_77 + '\x04';
      break;
    case 0x1f5:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      uVar6 = FUN_800221a0(0xffffffec,0xfffffff6);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a8 = FLOAT_803df9d8 * (float)(local_60 - DOUBLE_803dfa80);
      uStack100 = FUN_800221a0(0xfffffff6,10);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a4 = FLOAT_803df9d8 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80);
      uStack108 = FUN_800221a0(0xfffffff6,0);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      local_a0 = FLOAT_803df9d8 * (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803dfa80);
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = local_a8 + *(float *)(param_3 + 6);
        local_a4 = local_a4 + *(float *)(param_3 + 8);
        local_a0 = local_a0 + *(float *)(param_3 + 10);
      }
      uVar6 = FUN_800221a0(1,4);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9e0 * (float)(local_60 - DOUBLE_803dfa80);
      local_d0 = 0x19;
      local_78 = 0xff;
      local_94 = 0x80200;
      local_96 = 0x184;
      local_77 = FUN_800221a0(0,0x14);
      local_77 = local_77 + '\x04';
      break;
    case 0x1f6:
      uVar6 = FUN_800221a0(10,0x14);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9e4 * (float)(local_60 - DOUBLE_803dfa80);
      local_d0 = 0x14;
      local_78 = 0x40;
      local_94 = 0x80000;
      local_90 = 0x80;
      local_96 = 0x16d;
      local_77 = FUN_800221a0(0,0x14);
      local_77 = local_77 + '\x04';
      break;
    case 0x1f7:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_a4 = *(float *)(param_3 + 8);
      }
      local_9c = FLOAT_803df9e8;
      local_d0 = FUN_800221a0(0,0x1e);
      local_d0 = local_d0 + 0x46;
      local_78 = 0x7f;
      local_94 = 0x80110;
      local_96 = 0xc13;
      local_77 = ' ';
      break;
    case 0x1f8:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_9c = FLOAT_803df9e8;
      }
      else {
        local_9c = FLOAT_803df9e8 * *(float *)(param_3 + 4);
      }
      local_d0 = FUN_800221a0(0,0x1e);
      local_d0 = local_d0 + 0x46;
      local_78 = 100;
      local_94 = local_94 | 0x80100;
      local_96 = 0xc79;
      local_77 = '\0';
      local_80 = 0xe600;
      local_7e = 0x8800;
      local_7c = 0xa100;
      local_8c = 0xe600;
      local_88 = 0x8800;
      local_84 = 0xa100;
      local_90 = 0x20;
      break;
    default:
      uVar4 = 0xffffffff;
      goto LAB_800b8d4c;
    case 0x1fb:
      local_9c = FLOAT_803df9ec;
      local_d0 = 0x10;
      local_78 = 0xff;
      local_94 = 0x100114;
      local_96 = 0x17c;
      break;
    case 0x1fc:
      local_9c = FLOAT_803df9e8;
      local_d0 = 0x44;
      local_94 = 0x100201;
      local_96 = 0x4c;
      break;
    case 0x1fd:
      uVar6 = FUN_800221a0(0xfffffffd,3);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a4 = (float)(local_60 - DOUBLE_803dfa80);
      uStack100 = FUN_800221a0(0xfffffffd,3);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a0 = (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80);
      uStack108 = FUN_800221a0(0xffffffec,0x14);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      local_b4 = FLOAT_803df9f0 * (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803df9f0 * (float)(local_58 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xffffffec,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_ac = FLOAT_803df9f0 * (float)(local_50 - DOUBLE_803dfa80);
      local_9c = FLOAT_803df9f4;
      local_d0 = 0x1e;
      local_78 = 200;
      local_94 = 0x140101;
      iVar5 = FUN_800221a0(0,1);
      if (iVar5 == 0) {
        local_96 = 0xc7e;
      }
      else {
        local_96 = 0x33;
      }
      break;
    case 0x1fe:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      if (param_6 == (float *)0x0) {
        uVar4 = 0xffffffff;
        goto LAB_800b8d4c;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = *(float *)(param_3 + 6);
        local_a4 = *(float *)(param_3 + 8);
        local_a0 = *(float *)(param_3 + 10);
      }
      if (param_6 != (float *)0x0) {
        local_b4 = *param_6;
        uVar6 = FUN_800221a0(0,0x14);
        local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_b0 = FLOAT_803df9e8 * (float)(local_50 - DOUBLE_803dfa80);
        local_ac = param_6[1];
      }
      uVar6 = FUN_800221a0(0,10);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9fc * (float)(local_50 - DOUBLE_803dfa80) + FLOAT_803df9f8;
      local_d0 = FUN_800221a0(0xbe,0xfa);
      local_78 = 0x9b;
      local_94 = 0x1000000;
      local_96 = 0x23c;
      break;
    case 0x1ff:
      local_a4 = FLOAT_803dfa00;
      local_9c = FLOAT_803df9e0;
      local_d0 = 200;
      local_94 = 0x11000004;
      local_96 = 0x151;
      local_d4 = 0x200;
      break;
    case 0x200:
      FUN_8000bb18(psVar3,0x285);
      local_d0 = 100;
      local_50 = 4503601774854244.0;
      local_9c = FLOAT_803dfa04 * (float)(4503601774854244.0 - DOUBLE_803dfa80);
      local_94 = 0xa100201;
      local_96 = 0x56;
      break;
    case 0x201:
      uVar6 = FUN_800221a0(0xffffff9c,100);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a8 = (float)(local_50 - DOUBLE_803dfa80) / FLOAT_803dfa08;
      uVar6 = FUN_800221a0(0xffffffce,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a4 = (float)(local_58 - DOUBLE_803dfa80) / FLOAT_803dfa0c;
      uVar6 = FUN_800221a0(0xffffff9c,100);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a0 = (float)(local_60 - DOUBLE_803dfa80) / FLOAT_803dfa08;
      uStack100 = FUN_800221a0(1,5);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b0 = FLOAT_803df9e8 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80);
      local_9c = FLOAT_803dfa10;
      local_d0 = 100;
      local_77 = '\0';
      local_94 = 0x100201;
      local_96 = 99;
      break;
    case 0x202:
      uVar6 = FUN_800221a0(0x96,200);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = (FLOAT_803df9d8 * (float)(local_50 - DOUBLE_803dfa80)) / FLOAT_803dfa14;
      uVar6 = FUN_800221a0(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803dfa1c * ((float)(local_58 - DOUBLE_803dfa80) / FLOAT_803dfa14) +
                 FLOAT_803dfa18;
      local_d0 = (int)(*(float *)(param_3 + 4) / local_b0);
      local_60 = (double)(longlong)local_d0;
      if (local_d0 < 10) {
        local_d0 = 10;
      }
      if (0x78 < local_d0) {
        local_d0 = 0x78;
      }
      local_77 = '\0';
      local_94 = 0x201;
      local_90 = 0x4000000;
      local_96 = 0xc9f;
      local_78 = 0x60;
      break;
    case 0x203:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803dfa20;
      iVar5 = FUN_800221a0(0,3);
      if (iVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      else if (iVar5 < 2) {
        if (iVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
        else if (-1 < iVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
      }
      else if (iVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      local_9c = FLOAT_803dfa24;
      local_d0 = 0x3c;
      local_94 = 0x100210;
      local_96 = 0x184;
      local_78 = 0xc4;
      break;
    case 0x204:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803dfa20;
      iVar5 = FUN_800221a0(0,3);
      if (iVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      else if (iVar5 < 2) {
        if (iVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
        else if (-1 < iVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
      }
      else if (iVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      uVar6 = FUN_800221a0(0x28,0x50);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803dfa28 * (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0x28,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803dfa2c * (float)(local_58 - DOUBLE_803dfa80);
      local_d0 = 0x78;
      local_77 = '\0';
      local_94 = 0x80400110;
      local_96 = 0x47;
      break;
    case 0x205:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803dfa20;
      iVar5 = FUN_800221a0(0,3);
      if (iVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      else if (iVar5 < 2) {
        if (iVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
        else if (-1 < iVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
      }
      else if (iVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      uVar6 = FUN_800221a0(0x28,0x50);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803dfa28 * (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0x1e,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9fc * (float)(local_58 - DOUBLE_803dfa80);
      local_d0 = 0x96;
      local_78 = 0x9b;
      local_90 = 0x20;
      local_94 = 0x180210;
      sVar7 = FUN_800221a0(0,30000);
      local_80 = sVar7 + 0x63bf;
      iVar5 = FUN_800221a0(1,3);
      local_7e = (undefined2)((int)(uint)local_80 / iVar5);
      local_7c = 0;
      local_8c = FUN_800221a0(0,10000);
      iVar5 = FUN_800221a0(1,3);
      local_88 = (int)local_8c / iVar5;
      local_84 = 0;
      local_96 = 0x60;
      break;
    case 0x206:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
        param_3 = &DAT_8039c350;
      }
      local_a4 = *(float *)(param_3 + 8) - FLOAT_803dfa30;
      local_b0 = FLOAT_803dfa20;
      iVar5 = FUN_800221a0(0,3);
      if (iVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      else if (iVar5 < 2) {
        if (iVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
        else if (-1 < iVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar5 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar5;
          iVar1 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar1;
          uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
          local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803dfa80);
        }
      }
      else if (iVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar5 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar5;
        iVar1 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar1;
        uVar6 = FUN_800221a0((int)(short)iVar5,(int)(short)iVar1);
        local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803dfa80);
      }
      uVar6 = FUN_800221a0(0x50,100);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803dfa34 * (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0x1e,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803dfa1c * (float)(local_58 - DOUBLE_803dfa80);
      local_d0 = 0x96;
      local_78 = 0xff;
      local_94 = 0x80080110;
      local_96 = 0x60;
      break;
    case 0x208:
      uVar6 = FUN_800221a0(0xfffff448,3000);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a8 = FLOAT_803df9d8 * (float)(local_50 - DOUBLE_803dfa80);
      local_a4 = FLOAT_803dfa38;
      uVar6 = FUN_800221a0(0xfffff448,3000);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a0 = FLOAT_803df9d8 * (float)(local_58 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(400,600);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803dfa3c * (float)(local_60 - DOUBLE_803dfa80);
      uStack100 = FUN_800221a0(0xffffff9c,100);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b4 = FLOAT_803dfa04 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80);
      uStack108 = FUN_800221a0(0xffffff9c,100);
      uStack108 = uStack108 ^ 0x80000000;
      local_70 = 0x43300000;
      local_ac = FLOAT_803dfa04 * (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803dfa80);
      uStack68 = FUN_800221a0(0,10);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803dfa44 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfa80) +
                 FLOAT_803dfa40;
      local_d0 = 0xb4;
      local_78 = 0xff;
      local_94 = 0x80080000;
      local_90 = 0x100000;
      local_96 = 0xe7;
      break;
    case 0x209:
      uStack68 = FUN_800221a0(1,5);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(10,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803dfa48 * (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0,10);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803dfa4c *
                 (FLOAT_803df9fc * (float)(local_58 - DOUBLE_803dfa80) + FLOAT_803dfa50);
      local_d0 = FUN_800221a0(0x73,0x8c);
      local_78 = 0xff;
      local_94 = 0x80480200;
      local_96 = 0xc0d;
      break;
    case 0x20a:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c35c = FLOAT_803df9d0;
        DAT_8039c360 = FLOAT_803df9d0;
        DAT_8039c364 = FLOAT_803df9d0;
        DAT_8039c358 = FLOAT_803df9d4;
        DAT_8039c350 = 0;
        DAT_8039c352 = 0;
        DAT_8039c354 = 0;
      }
      uStack68 = FUN_800221a0(0xfffffffb,5);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(1,5);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a4 = (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xfffffffb,5);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_a0 = (float)(local_58 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0,600);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      dVar10 = (double)(FLOAT_803df9e0 * (float)(local_60 - DOUBLE_803dfa80) + FLOAT_803dfa54);
      uStack100 = FUN_800221a0(0,200);
      uStack100 = uStack100 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b0 = FLOAT_803dfa10 * (float)((double)CONCAT44(0x43300000,uStack100) - DOUBLE_803dfa80)
                 + FLOAT_803df9d4;
      uStack108 = (int)*psVar3 ^ 0x80000000;
      local_70 = 0x43300000;
      dVar9 = (double)FUN_80293e80((double)((FLOAT_803dfa58 *
                                            (float)((double)CONCAT44(0x43300000,uStack108) -
                                                   DOUBLE_803dfa80)) / FLOAT_803dfa5c));
      local_b4 = (float)dVar9;
      uStack60 = (int)*psVar3 ^ 0x80000000;
      local_40 = 0x43300000;
      dVar9 = (double)FUN_80294204((double)((FLOAT_803dfa58 *
                                            (float)((double)CONCAT44(0x43300000,uStack60) -
                                                   DOUBLE_803dfa80)) / FLOAT_803dfa5c));
      local_ac = (float)dVar9;
      uStack52 = FUN_800221a0(0,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      fVar2 = (float)(dVar10 * (double)(FLOAT_803dfa60 *
                                       (float)((double)CONCAT44(0x43300000,uStack52) -
                                              DOUBLE_803dfa80)) + (double)FLOAT_803df9d8);
      local_b4 = local_b4 * fVar2;
      local_ac = local_ac * fVar2;
      local_b0 = (float)((double)local_b0 * dVar10);
      uStack44 = FUN_800221a0(0,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_9c = FLOAT_803dfa68 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfa80) +
                 FLOAT_803dfa64;
      local_d0 = FUN_800221a0(0xb4,200);
      local_78 = 0xff;
      local_94 = 0x3000120;
      local_90 = 0x200000;
      local_96 = 0xc0a;
      local_d4 = 0x20b;
      break;
    case 0x20b:
      uStack44 = FUN_800221a0(2,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_b0 = FLOAT_803df9f0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfa80);
      local_9c = FLOAT_803dfa6c;
      local_d0 = 0x1e;
      local_78 = 0x9b;
      local_94 = 0x180100;
      local_96 = 0x5f;
      local_80 = 0xffff;
      iVar5 = FUN_800221a0(0,50000);
      local_88 = iVar5 + 0x3cafU & 0xffff;
      local_7e = (undefined2)local_88;
      local_7c = 0;
      local_8c = (uint)local_80;
      local_84 = 0;
      local_90 = 0x20;
      break;
    case 0x20c:
      uStack44 = FUN_800221a0(0xffffffc9,0x37);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfa80);
      uStack52 = FUN_800221a0(10,0xf);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfa80);
      uStack60 = FUN_800221a0(0xffffffc9,0x37);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfa80);
      uStack68 = FUN_800221a0(0xfffffff8,8);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_b4 = FLOAT_803dfa24 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(10,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_b0 = FLOAT_803df9d8 * (float)(local_50 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xfffffff8,8);
      local_58 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_ac = FLOAT_803dfa24 * (float)(local_58 - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0,10);
      local_60 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803df9fc * (float)(local_60 - DOUBLE_803dfa80) + FLOAT_803dfa70;
      local_d0 = FUN_800221a0(0x78,0x8c);
      local_78 = 0xff;
      local_d4 = 0x20b;
      local_90 = 0x200000;
      local_94 = 0x1001100;
      local_96 = 0xc0a;
      break;
    case 0x20d:
      uStack44 = FUN_800221a0(0xffffffce,0x32);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_b4 = FLOAT_803dfa74 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfa80);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_b0 = FLOAT_803dfa78 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfa80);
      uStack60 = FUN_800221a0(0xffffffce,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_ac = FLOAT_803dfa74 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfa80);
      uStack68 = FUN_800221a0(0,400);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803df9d8 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfa80);
      uVar6 = FUN_800221a0(0xf,0x19);
      local_50 = (double)CONCAT44(0x43300000,uVar6 ^ 0x80000000);
      local_9c = FLOAT_803dfa04 * (float)(local_50 - DOUBLE_803dfa80);
      local_d0 = 100;
      local_94 = 0x4a0104;
      local_90 = 0x40008;
      local_c0 = FLOAT_803df9d0;
      local_bc = FLOAT_803df9d0;
      local_b8 = FLOAT_803df9d0;
      local_cc = 0x46;
      local_ca = 0;
      local_c8 = 0;
      local_c4 = FLOAT_803df9d4;
      local_96 = 0xe0;
      break;
    case 0x20e:
      local_a4 = FLOAT_803dfa38;
      local_9c = FLOAT_803df9f0;
      local_d0 = 200;
      local_94 = 0x11800004;
      local_78 = 0xa0;
      local_96 = 0x151;
      local_d4 = 0x200;
    }
    local_94 = local_94 | param_4;
    if (((local_94 & 1) != 0) && ((local_94 & 2) != 0)) {
      local_94 = local_94 ^ 2;
    }
    if ((local_94 & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_d8 != (short *)0x0) {
          local_a8 = local_a8 + *(float *)(local_d8 + 0xc);
          local_a4 = local_a4 + *(float *)(local_d8 + 0xe);
          local_a0 = local_a0 + *(float *)(local_d8 + 0x10);
        }
      }
      else {
        local_a8 = local_a8 + local_c0;
        local_a4 = local_a4 + local_bc;
        local_a0 = local_a0 + local_b8;
      }
    }
    uVar4 = (**(code **)(*DAT_803dca78 + 8))(&local_d8,0xffffffff,(int)uVar11,0);
  }
LAB_800b8d4c:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286124(uVar4);
  return;
}

