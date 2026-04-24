// Function: FUN_800b7184
// Entry: 800b7184
// Size: 7796 bytes

/* WARNING: Removing unreachable block (ram,0x800b8fd8) */
/* WARNING: Removing unreachable block (ram,0x800b7194) */

void FUN_800b7184(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,float *param_6)

{
  int iVar1;
  int iVar2;
  float fVar3;
  short *psVar4;
  uint uVar5;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps31_1;
  undefined8 uVar8;
  short *local_d8;
  undefined4 local_d4;
  uint local_d0;
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
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar8 = FUN_8028683c();
  psVar4 = (short *)((ulonglong)uVar8 >> 0x20);
  if (psVar4 != (short *)0x0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800b8fd8;
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
    local_7a = (undefined)uVar8;
    local_a8 = FLOAT_803e0650;
    local_a4 = FLOAT_803e0650;
    local_a0 = FLOAT_803e0650;
    local_b4 = FLOAT_803e0650;
    local_b0 = FLOAT_803e0650;
    local_ac = FLOAT_803e0650;
    local_9c = FLOAT_803e0650;
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
    local_d8 = psVar4;
    switch((int)uVar8) {
    case 500:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      uStack_6c = FUN_80022264(0xffffffec,0xfffffff6);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      local_a8 = FLOAT_803e0658 * (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e0700);
      uStack_64 = FUN_80022264(0xfffffff6,10);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a4 = FLOAT_803e0658 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xfffffff6,0);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a0 = FLOAT_803e0658 * (float)(local_60 - DOUBLE_803e0700);
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = local_a8 + *(float *)(param_3 + 6);
        local_a4 = local_a4 + *(float *)(param_3 + 8);
        local_a0 = local_a0 + *(float *)(param_3 + 10);
      }
      uVar5 = FUN_80022264(0xd,0x14);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e065c * (float)(local_60 - DOUBLE_803e0700);
      local_d0 = 0x19;
      local_78 = 0xff;
      local_94 = 0x80200;
      local_90 = 0x4000800;
      local_96 = 0x184;
      uVar5 = FUN_80022264(0,0x14);
      local_77 = (char)uVar5 + '\x04';
      break;
    case 0x1f5:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      uVar5 = FUN_80022264(0xffffffec,0xfffffff6);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a8 = FLOAT_803e0658 * (float)(local_60 - DOUBLE_803e0700);
      uStack_64 = FUN_80022264(0xfffffff6,10);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a4 = FLOAT_803e0658 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700);
      uStack_6c = FUN_80022264(0xfffffff6,0);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      local_a0 = FLOAT_803e0658 * (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e0700);
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = local_a8 + *(float *)(param_3 + 6);
        local_a4 = local_a4 + *(float *)(param_3 + 8);
        local_a0 = local_a0 + *(float *)(param_3 + 10);
      }
      uVar5 = FUN_80022264(1,4);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e0660 * (float)(local_60 - DOUBLE_803e0700);
      local_d0 = 0x19;
      local_78 = 0xff;
      local_94 = 0x80200;
      local_96 = 0x184;
      uVar5 = FUN_80022264(0,0x14);
      local_77 = (char)uVar5 + '\x04';
      break;
    case 0x1f6:
      uVar5 = FUN_80022264(10,0x14);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e0664 * (float)(local_60 - DOUBLE_803e0700);
      local_d0 = 0x14;
      local_78 = 0x40;
      local_94 = 0x80000;
      local_90 = 0x80;
      local_96 = 0x16d;
      uVar5 = FUN_80022264(0,0x14);
      local_77 = (char)uVar5 + '\x04';
      break;
    case 0x1f7:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      if (param_3 != (undefined2 *)0x0) {
        local_a4 = *(float *)(param_3 + 8);
      }
      local_9c = FLOAT_803e0668;
      local_d0 = FUN_80022264(0,0x1e);
      local_d0 = local_d0 + 0x46;
      local_78 = 0x7f;
      local_94 = 0x80110;
      local_96 = 0xc13;
      local_77 = ' ';
      break;
    case 0x1f8:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      if (param_3 == (undefined2 *)0x0) {
        local_9c = FLOAT_803e0668;
      }
      else {
        local_9c = FLOAT_803e0668 * *(float *)(param_3 + 4);
      }
      local_d0 = FUN_80022264(0,0x1e);
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
      goto LAB_800b8fd8;
    case 0x1fb:
      local_9c = FLOAT_803e066c;
      local_d0 = 0x10;
      local_78 = 0xff;
      local_94 = 0x100114;
      local_96 = 0x17c;
      break;
    case 0x1fc:
      local_9c = FLOAT_803e0668;
      local_d0 = 0x44;
      local_94 = 0x100201;
      local_96 = 0x4c;
      break;
    case 0x1fd:
      uVar5 = FUN_80022264(0xfffffffd,3);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a4 = (float)(local_60 - DOUBLE_803e0700);
      uStack_64 = FUN_80022264(0xfffffffd,3);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_a0 = (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700);
      uStack_6c = FUN_80022264(0xffffffec,0x14);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      local_b4 = FLOAT_803e0670 * (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xffffffec,0x14);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e0670 * (float)(local_58 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xffffffec,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_ac = FLOAT_803e0670 * (float)(local_50 - DOUBLE_803e0700);
      local_9c = FLOAT_803e0674;
      local_d0 = 0x1e;
      local_78 = 200;
      local_94 = 0x140101;
      uVar5 = FUN_80022264(0,1);
      if (uVar5 == 0) {
        local_96 = 0xc7e;
      }
      else {
        local_96 = 0x33;
      }
      break;
    case 0x1fe:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      if (param_6 == (float *)0x0) goto LAB_800b8fd8;
      if (param_3 != (undefined2 *)0x0) {
        local_a8 = *(float *)(param_3 + 6);
        local_a4 = *(float *)(param_3 + 8);
        local_a0 = *(float *)(param_3 + 10);
      }
      if (param_6 != (float *)0x0) {
        local_b4 = *param_6;
        uVar5 = FUN_80022264(0,0x14);
        local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_b0 = FLOAT_803e0668 * (float)(local_50 - DOUBLE_803e0700);
        local_ac = param_6[1];
      }
      uVar5 = FUN_80022264(0,10);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e067c * (float)(local_50 - DOUBLE_803e0700) + FLOAT_803e0678;
      local_d0 = FUN_80022264(0xbe,0xfa);
      local_78 = 0x9b;
      local_94 = 0x1000000;
      local_96 = 0x23c;
      break;
    case 0x1ff:
      local_a4 = FLOAT_803e0680;
      local_9c = FLOAT_803e0660;
      local_d0 = 200;
      local_94 = 0x11000004;
      local_96 = 0x151;
      local_d4 = 0x200;
      break;
    case 0x200:
      FUN_8000bb38((uint)psVar4,0x285);
      local_d0 = 100;
      local_50 = 4503601774854244.0;
      local_9c = FLOAT_803e0684 * (float)(4503601774854244.0 - DOUBLE_803e0700);
      local_94 = 0xa100201;
      local_96 = 0x56;
      break;
    case 0x201:
      uVar5 = FUN_80022264(0xffffff9c,100);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a8 = (float)(local_50 - DOUBLE_803e0700) / FLOAT_803e0688;
      uVar5 = FUN_80022264(0xffffffce,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a4 = (float)(local_58 - DOUBLE_803e0700) / FLOAT_803e068c;
      uVar5 = FUN_80022264(0xffffff9c,100);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a0 = (float)(local_60 - DOUBLE_803e0700) / FLOAT_803e0688;
      uStack_64 = FUN_80022264(1,5);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b0 = FLOAT_803e0668 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700);
      local_9c = FLOAT_803e0690;
      local_d0 = 100;
      local_77 = '\0';
      local_94 = 0x100201;
      local_96 = 99;
      break;
    case 0x202:
      uVar5 = FUN_80022264(0x96,200);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = (FLOAT_803e0658 * (float)(local_50 - DOUBLE_803e0700)) / FLOAT_803e0694;
      uVar5 = FUN_80022264(0x32,100);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e069c * ((float)(local_58 - DOUBLE_803e0700) / FLOAT_803e0694) +
                 FLOAT_803e0698;
      local_d0 = (uint)(*(float *)(param_3 + 4) / local_b0);
      local_60 = (double)(longlong)(int)local_d0;
      if ((int)local_d0 < 10) {
        local_d0 = 10;
      }
      if (0x78 < (int)local_d0) {
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
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803e06a0;
      uVar5 = FUN_80022264(0,3);
      if (uVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      else if ((int)uVar5 < 2) {
        if (uVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
        else if (-1 < (int)uVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
      }
      else if ((int)uVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      local_9c = FLOAT_803e06a4;
      local_d0 = 0x3c;
      local_94 = 0x100210;
      local_96 = 0x184;
      local_78 = 0xc4;
      break;
    case 0x204:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803e06a0;
      uVar5 = FUN_80022264(0,3);
      if (uVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      else if ((int)uVar5 < 2) {
        if (uVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
        else if (-1 < (int)uVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
      }
      else if ((int)uVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      uVar5 = FUN_80022264(0x28,0x50);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e06a8 * (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0x28,0x50);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e06ac * (float)(local_58 - DOUBLE_803e0700);
      local_d0 = 0x78;
      local_77 = '\0';
      local_94 = 0x80400110;
      local_96 = 0x47;
      break;
    case 0x205:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      local_a4 = *(float *)(param_3 + 8);
      local_b0 = FLOAT_803e06a0;
      uVar5 = FUN_80022264(0,3);
      if (uVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      else if ((int)uVar5 < 2) {
        if (uVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
        else if (-1 < (int)uVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
      }
      else if ((int)uVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      uVar5 = FUN_80022264(0x28,0x50);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e06a8 * (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0x1e,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e067c * (float)(local_58 - DOUBLE_803e0700);
      local_d0 = 0x96;
      local_78 = 0x9b;
      local_90 = 0x20;
      local_94 = 0x180210;
      uVar5 = FUN_80022264(0,30000);
      local_80 = (short)uVar5 + 0x63bf;
      uVar5 = FUN_80022264(1,3);
      local_7e = (undefined2)((int)(uint)local_80 / (int)uVar5);
      local_7c = 0;
      local_8c = FUN_80022264(0,10000);
      local_88 = FUN_80022264(1,3);
      local_88 = (int)local_8c / (int)local_88;
      local_84 = 0;
      local_96 = 0x60;
      break;
    case 0x206:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
        param_3 = &DAT_8039cfb0;
      }
      local_a4 = *(float *)(param_3 + 8) - FLOAT_803e06b0;
      local_b0 = FLOAT_803e06a0;
      uVar5 = FUN_80022264(0,3);
      if (uVar5 == 2) {
        local_a0 = *(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      else if ((int)uVar5 < 2) {
        if (uVar5 == 0) {
          local_a8 = *(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
        else if (-1 < (int)uVar5) {
          local_a8 = -*(float *)(param_3 + 6);
          iVar1 = (int)-*(float *)(param_3 + 10);
          local_50 = (double)(longlong)iVar1;
          iVar2 = (int)*(float *)(param_3 + 10);
          local_58 = (double)(longlong)iVar2;
          uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
          local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_a0 = (float)(local_60 - DOUBLE_803e0700);
        }
      }
      else if ((int)uVar5 < 4) {
        local_a0 = -*(float *)(param_3 + 10);
        iVar1 = (int)-*(float *)(param_3 + 6);
        local_50 = (double)(longlong)iVar1;
        iVar2 = (int)*(float *)(param_3 + 6);
        local_58 = (double)(longlong)iVar2;
        uVar5 = FUN_80022264((int)(short)iVar1,(int)(short)iVar2);
        local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
        local_a8 = (float)(local_60 - DOUBLE_803e0700);
      }
      uVar5 = FUN_80022264(0x50,100);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e06b4 * (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0x1e,0x32);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e069c * (float)(local_58 - DOUBLE_803e0700);
      local_d0 = 0x96;
      local_78 = 0xff;
      local_94 = 0x80080110;
      local_96 = 0x60;
      break;
    case 0x208:
      uVar5 = FUN_80022264(0xfffff448,3000);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a8 = FLOAT_803e0658 * (float)(local_50 - DOUBLE_803e0700);
      local_a4 = FLOAT_803e06b8;
      uVar5 = FUN_80022264(0xfffff448,3000);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a0 = FLOAT_803e0658 * (float)(local_58 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(400,600);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e06bc * (float)(local_60 - DOUBLE_803e0700);
      uStack_64 = FUN_80022264(0xffffff9c,100);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b4 = FLOAT_803e0684 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700);
      uStack_6c = FUN_80022264(0xffffff9c,100);
      uStack_6c = uStack_6c ^ 0x80000000;
      local_70 = 0x43300000;
      local_ac = FLOAT_803e0684 * (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e0700);
      uStack_44 = FUN_80022264(0,10);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803e06c4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0700)
                 + FLOAT_803e06c0;
      local_d0 = 0xb4;
      local_78 = 0xff;
      local_94 = 0x80080000;
      local_90 = 0x100000;
      local_96 = 0xe7;
      break;
    case 0x209:
      uStack_44 = FUN_80022264(1,5);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(10,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e06c8 * (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0,10);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e06cc *
                 (FLOAT_803e067c * (float)(local_58 - DOUBLE_803e0700) + FLOAT_803e06d0);
      local_d0 = FUN_80022264(0x73,0x8c);
      local_78 = 0xff;
      local_94 = 0x80480200;
      local_96 = 0xc0d;
      break;
    case 0x20a:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfbc = FLOAT_803e0650;
        DAT_8039cfc0 = FLOAT_803e0650;
        DAT_8039cfc4 = FLOAT_803e0650;
        DAT_8039cfb8 = FLOAT_803e0654;
        DAT_8039cfb0 = 0;
        DAT_8039cfb2 = 0;
        DAT_8039cfb4 = 0;
      }
      uStack_44 = FUN_80022264(0xfffffffb,5);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(1,5);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a4 = (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xfffffffb,5);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_a0 = (float)(local_58 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0,600);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      dVar7 = (double)(FLOAT_803e0660 * (float)(local_60 - DOUBLE_803e0700) + FLOAT_803e06d4);
      uStack_64 = FUN_80022264(0,200);
      uStack_64 = uStack_64 ^ 0x80000000;
      local_68 = 0x43300000;
      local_b0 = FLOAT_803e0690 * (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e0700)
                 + FLOAT_803e0654;
      uStack_6c = (int)*psVar4 ^ 0x80000000;
      local_70 = 0x43300000;
      dVar6 = (double)FUN_802945e0();
      local_b4 = (float)dVar6;
      uStack_3c = (int)*psVar4 ^ 0x80000000;
      local_40 = 0x43300000;
      dVar6 = (double)FUN_80294964();
      local_ac = (float)dVar6;
      uStack_34 = FUN_80022264(0,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      fVar3 = (float)(dVar7 * (double)(FLOAT_803e06e0 *
                                      (float)((double)CONCAT44(0x43300000,uStack_34) -
                                             DOUBLE_803e0700)) + (double)FLOAT_803e0658);
      local_b4 = local_b4 * fVar3;
      local_ac = local_ac * fVar3;
      local_b0 = (float)((double)local_b0 * dVar7);
      uStack_2c = FUN_80022264(0,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_9c = FLOAT_803e06e8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0700)
                 + FLOAT_803e06e4;
      local_d0 = FUN_80022264(0xb4,200);
      local_78 = 0xff;
      local_94 = 0x3000120;
      local_90 = 0x200000;
      local_96 = 0xc0a;
      local_d4 = 0x20b;
      break;
    case 0x20b:
      uStack_2c = FUN_80022264(2,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_b0 = FLOAT_803e0670 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0700);
      local_9c = FLOAT_803e06ec;
      local_d0 = 0x1e;
      local_78 = 0x9b;
      local_94 = 0x180100;
      local_96 = 0x5f;
      local_80 = 0xffff;
      uVar5 = FUN_80022264(0,50000);
      local_88 = uVar5 + 0x3caf & 0xffff;
      local_7e = (undefined2)(uVar5 + 0x3caf);
      local_7c = 0;
      local_8c = (uint)local_80;
      local_84 = 0;
      local_90 = 0x20;
      break;
    case 0x20c:
      uStack_2c = FUN_80022264(0xffffffc9,0x37);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_a8 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0700);
      uStack_34 = FUN_80022264(10,0xf);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0700);
      uStack_3c = FUN_80022264(0xffffffc9,0x37);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0700);
      uStack_44 = FUN_80022264(0xfffffff8,8);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_b4 = FLOAT_803e06a4 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(10,0x14);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_b0 = FLOAT_803e0658 * (float)(local_50 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xfffffff8,8);
      local_58 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_ac = FLOAT_803e06a4 * (float)(local_58 - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0,10);
      local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e067c * (float)(local_60 - DOUBLE_803e0700) + FLOAT_803e06f0;
      local_d0 = FUN_80022264(0x78,0x8c);
      local_78 = 0xff;
      local_d4 = 0x20b;
      local_90 = 0x200000;
      local_94 = 0x1001100;
      local_96 = 0xc0a;
      break;
    case 0x20d:
      uStack_2c = FUN_80022264(0xffffffce,0x32);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_b4 = FLOAT_803e06f4 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0700);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_b0 = FLOAT_803e06f8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0700);
      uStack_3c = FUN_80022264(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_ac = FLOAT_803e06f4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0700);
      uStack_44 = FUN_80022264(0,400);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0658 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0700);
      uVar5 = FUN_80022264(0xf,0x19);
      local_50 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
      local_9c = FLOAT_803e0684 * (float)(local_50 - DOUBLE_803e0700);
      local_d0 = 100;
      local_94 = 0x4a0104;
      local_90 = 0x40008;
      local_c0 = FLOAT_803e0650;
      local_bc = FLOAT_803e0650;
      local_b8 = FLOAT_803e0650;
      local_cc = 0x46;
      local_ca = 0;
      local_c8 = 0;
      local_c4 = FLOAT_803e0654;
      local_96 = 0xe0;
      break;
    case 0x20e:
      local_a4 = FLOAT_803e06b8;
      local_9c = FLOAT_803e0670;
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
    (**(code **)(*DAT_803dd6f8 + 8))(&local_d8,0xffffffff,(int)uVar8,0);
  }
LAB_800b8fd8:
  FUN_80286888();
  return;
}

