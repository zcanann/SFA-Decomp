// Function: FUN_800be2c0
// Entry: 800be2c0
// Size: 6160 bytes

void FUN_800be2c0(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,int param_6)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined8 uVar4;
  int local_c8 [3];
  undefined2 local_bc;
  undefined2 local_ba;
  undefined2 local_b8;
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
  short local_86;
  code *local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined2 local_70;
  short local_6e;
  undefined2 local_6c;
  undefined local_6a;
  undefined local_68;
  char local_67;
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
  undefined8 local_30;
  
  uVar4 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar2 = FUN_8002bac4();
  FLOAT_803dc460 = FLOAT_803dc460 + FLOAT_803e0958;
  if (FLOAT_803e0960 < FLOAT_803dc460) {
    FLOAT_803dc460 = FLOAT_803e095c;
  }
  FLOAT_803dc464 = FLOAT_803dc464 + FLOAT_803e0964;
  if (FLOAT_803e0960 < FLOAT_803dc464) {
    FLOAT_803dc464 = FLOAT_803e0968;
  }
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) goto LAB_800bfab8;
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
    local_6a = (undefined)uVar4;
    local_98 = FLOAT_803e096c;
    local_94 = FLOAT_803e096c;
    local_90 = FLOAT_803e096c;
    local_a4 = FLOAT_803e096c;
    local_a0 = FLOAT_803e096c;
    local_9c = FLOAT_803e096c;
    local_8c = FLOAT_803e096c;
    local_c8[2] = 0;
    local_c8[1] = 0xffffffff;
    local_68 = 0xff;
    local_67 = '\0';
    local_86 = 0;
    local_70 = 0xffff;
    local_6e = -1;
    local_6c = 0xffff;
    local_7c = 0xffff;
    local_78 = 0xffff;
    local_74 = 0xffff;
    local_88 = 0;
    local_c8[0] = iVar1;
    switch((int)uVar4) {
    case 0x84:
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e0998 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(4,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0xffffffd8,0x28);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803e099c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0x28,0x50);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e09a0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      local_c8[2] = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x1400211;
      local_86 = 0xdf;
      break;
    case 0x85:
      if (param_6 == 0) goto LAB_800bfab8;
      local_98 = *(float *)(iVar2 + 0x18);
      local_94 = *(float *)(iVar2 + 0x1c);
      local_90 = *(float *)(iVar2 + 0x20);
      local_8c = FLOAT_803e09a4;
      local_c8[2] = 0x28;
      local_68 = 0xff;
      local_84 = (code *)0x110;
      local_86 = param_3[2] + 0x170;
      break;
    default:
      goto LAB_800bfab8;
    case 0x8a:
      local_98 = FLOAT_803e09a8;
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_a4 = FLOAT_803e09ac;
      uStack_44 = FUN_80022264(0x28,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e09b0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      local_c8[2] = 0x10e;
      local_67 = '\x10';
      local_68 = 0xf;
      local_84 = (code *)0x2000011;
      local_86 = 0x5f;
      break;
    case 0x8b:
      uStack_34 = FUN_80022264(0xffffff88,0x78);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffff88,0x78);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0xffffff88,0x78);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e09b4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(4,10);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e09b4 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uStack_5c = FUN_80022264(0xffffffd8,0x28);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e09b4 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a08);
      uVar3 = FUN_80022264(0x28,0x50);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e09b8 * (float)(local_30 - DOUBLE_803e0a08);
      local_c8[2] = 0x46;
      local_68 = 0xff;
      local_c8[1] = 0x378;
      local_84 = (code *)&DAT_80000119;
      local_86 = 0x125;
      break;
    case 0x8c:
    case 0x8d:
    case 0x9d:
    case 0x9e:
    case 0xa5:
    case 0xa6:
      break;
    case 0x8e:
      uVar3 = FUN_80022264(0xffffffd8,0x28);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a4 = FLOAT_803e09bc * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e09bc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e09bc * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_8c = FLOAT_803e09bc;
      local_c8[2] = 0x50;
      local_68 = 0xff;
      local_84 = (code *)0x100110;
      local_86 = 0x30;
      break;
    case 0x8f:
      uVar3 = FUN_80022264(0xfffffffa,6);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_98 = (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xfffffffa,6);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xfffffffa,6);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0xffffffd8,0x28);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e099c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0xffffffd8,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e099c * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(0xffffffd8,0x28);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e099c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uVar3 = FUN_80022264(0,0xc);
      if (uVar3 == 0) {
        uVar3 = FUN_80022264(0xf,0x1e);
        local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803e09c0 * (float)(local_30 - DOUBLE_803e0a08);
        local_68 = 0x5f;
      }
      else {
        uVar3 = FUN_80022264(0xf,0x1e);
        local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803e09c4 * (float)(local_30 - DOUBLE_803e0a08);
        local_68 = 0xff;
      }
      local_c8[2] = 0x1e;
      local_84 = (code *)0x400108;
      local_86 = 0x33;
      break;
    case 0x9a:
      local_98 = FLOAT_803e09c8;
      uVar3 = FUN_80022264(0xffffffbe,0x42);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_94 = FLOAT_803e09cc + (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xffffffbe,0x42);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(1,10);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(0x50,0x78);
      local_68 = 0xff;
      local_84 = (code *)0x100210;
      local_86 = 0x125;
      local_67 = '\x05';
      break;
    case 0x9b:
      uVar3 = FUN_80022264(0xffffffbe,0x42);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_98 = (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0,0x42);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e09cc - (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffffa0,0x60);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0,0x28);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a0 = FLOAT_803e09d0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(10,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e09d4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(0,0x1e);
      local_c8[2] = local_c8[2] + 0x1e;
      local_68 = 0xff;
      local_84 = (code *)0x100200;
      local_86 = 0x125;
      break;
    case 0x9c:
      uVar3 = FUN_80022264(0xffffffd8,0x28);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a4 = FLOAT_803e09d0 * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e09d0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e09d0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_8c = FLOAT_803e09d8;
      local_c8[2] = 0x1e;
      local_68 = 0xff;
      local_84 = (code *)0x110;
      local_86 = 0xdd;
      break;
    case 0x9f:
      uVar3 = FUN_80022264(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a4 = FLOAT_803e09dc * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e09dc * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e09dc * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_8c = FLOAT_803e09d4;
      local_c8[2] = FUN_80022264(0x23,0x4b);
      local_84 = (code *)0x81480000;
      local_80 = 0x410800;
      local_86 = 0x167;
      break;
    case 0xa0:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039cfd4 = FLOAT_803e096c;
        DAT_8039cfd8 = FLOAT_803e096c;
        DAT_8039cfdc = FLOAT_803e096c;
        DAT_8039cfd0 = FLOAT_803e0960;
        DAT_8039cfc8 = 0;
        DAT_8039cfca = 0;
        DAT_8039cfcc = 0;
        param_3 = &DAT_8039cfc8;
      }
      uVar3 = FUN_80022264(0xffffffec,0xfffffff6);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_98 = FLOAT_803e095c * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xfffffff6,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xfffffff6,0);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_68 = 0xff;
      if (param_3 != (undefined2 *)0x0) {
        local_98 = local_98 + *(float *)(param_3 + 6);
        local_94 = local_94 + *(float *)(param_3 + 8);
        local_90 = local_90 + *(float *)(param_3 + 10);
        if (FLOAT_803e0960 == *(float *)(param_3 + 4)) {
          local_68 = 0xff;
        }
        else {
          iVar1 = (int)(FLOAT_803e09e0 * *(float *)(param_3 + 4));
          local_30 = (double)(longlong)iVar1;
          local_68 = (undefined)iVar1;
        }
      }
      uVar3 = FUN_80022264(10,0x14);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e09e4 * (float)(local_30 - DOUBLE_803e0a08);
      local_c8[2] = 0x2d;
      local_84 = (code *)0x200;
      local_86 = 0x125;
      uVar3 = FUN_80022264(0,0x14);
      local_67 = (char)uVar3 + '\x04';
      break;
    case 0xa1:
      uVar3 = FUN_80022264(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a0 = FLOAT_803e09e8 * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(100,0x96);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803e09ec * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803e09f0 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0xffffff9c,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803e09f0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0x32,200);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803e09f4 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      local_c8[2] = 0x96;
      local_86 = 0xc10;
      local_84 = FUN_80080100;
      local_80 = 0x4020020;
      uVar3 = FUN_80022264(0x7f,0xff);
      local_68 = (undefined)uVar3;
      local_7c = 0xa70f;
      local_70 = 0xa70f;
      local_78 = 0xa70f;
      local_6e = -0x58f1;
      local_74 = 50000;
      local_6c = 50000;
      break;
    case 0xa3:
      if (param_3 != (undefined2 *)0x0) {
        local_98 = *(float *)(param_3 + 6);
        local_94 = *(float *)(param_3 + 8);
        local_90 = *(float *)(param_3 + 10);
        uVar3 = FUN_80022264(100,0x78);
        local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_9c = FLOAT_803e09f8 * (float)(local_30 - DOUBLE_803e0a08);
        uStack_34 = FUN_80022264(0x3c,0x50);
        uStack_34 = uStack_34 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = FLOAT_803e09fc *
                   (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
        uVar3 = FUN_80022264(0,5);
        local_c8[2] = uVar3 + (int)(short)param_3[3] + 7;
        local_86 = 0x185;
        local_84 = (code *)0xc0080004;
        local_80 = 0x4420800;
      }
      break;
    case 0xa7:
      uVar3 = FUN_80022264(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_a4 = FLOAT_803e0a00 * (float)(local_30 - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(0xffffff9c,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803e0a00 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      uStack_3c = FUN_80022264(0xffffff9c,100);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803e0a00 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0x23,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e09a0 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(10,0x28);
      local_c8[2] = local_c8[2] + 10;
      local_86 = 0xc13;
      local_84 = (code *)0x81080010;
      local_80 = 0x482800;
      break;
    case 0xa8:
      local_8c = FLOAT_803e095c;
      local_c8[2] = 0xe;
      local_84 = (code *)0x480100;
      local_80 = 0x4000800;
      local_86 = 0x5fd;
      local_68 = 100;
      break;
    case 0xa9:
      if (param_3 == (undefined2 *)0x0) {
        uVar3 = FUN_80022264(0x4b,100);
        local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = FLOAT_803e09a0 * (float)(local_30 - DOUBLE_803e0a08);
      }
      else {
        uVar3 = FUN_80022264(0x4b,100);
        local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
        local_8c = *(float *)(param_3 + 4) * FLOAT_803e09a0 * (float)(local_30 - DOUBLE_803e0a08);
      }
      local_c8[2] = 1;
      local_84 = (code *)0x80010;
      local_80 = 0x800;
      local_86 = 0xc7e;
      local_68 = 0x96;
      break;
    case 0xaa:
      uVar3 = FUN_80022264(0x96,200);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e0a04 * (float)(local_30 - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(0xf,0x19);
      local_86 = 0x185;
      local_84 = (code *)0x80180200;
      local_80 = 0x4000000;
      local_68 = 0x96;
      break;
    case 0xab:
      uVar3 = FUN_80022264(100,0x96);
      local_30 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
      local_8c = FLOAT_803e0a04 * (float)(local_30 - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(0x19,0x2d);
      local_86 = 0x185;
      local_84 = (code *)0x80180210;
      local_80 = 0x4000800;
      break;
    case 0xac:
      uStack_3c = FUN_80022264(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_94 = FLOAT_803e096c;
      uStack_44 = FUN_80022264(0xffffffce,0x32);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0xfffffff8,8);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(9,0xc);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e0990 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uStack_5c = FUN_80022264(0xfffffff8,8);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a08);
      uStack_34 = FUN_80022264(10,0xf);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e0994 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0a08);
      local_c8[2] = FUN_80022264(0,0x14);
      local_c8[2] = local_c8[2] + 0x5f;
      local_68 = 0xff;
      local_86 = 0x60;
      local_70 = 0x3caf;
      local_6e = 0x3caf;
      local_6c = 0x3caf;
      local_7c = 0xa70f;
      local_78 = 0xa70f;
      local_74 = 0xa70f;
      local_67 = '\0';
      local_84 = (code *)0x80180100;
      local_80 = 0x20;
      break;
    case 0xad:
      uStack_44 = FUN_80022264(0xffffffe2,0x1e);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(6,0x16);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0988 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(0xffffffe2,0x1e);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0984 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uStack_5c = FUN_80022264(0xffffffce,0x32);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_98 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a08);
      local_94 = FLOAT_803e096c;
      uStack_3c = FUN_80022264(0xffffffce,0x32);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803e095c * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0a08);
      local_8c = FLOAT_803e098c;
      local_c8[2] = 0x91;
      local_68 = 0xff;
      local_70 = 0xffff;
      uVar3 = FUN_80022264(0,10000);
      local_6e = (short)uVar3 + 0x3caf;
      local_6c = 0x3caf;
      local_7c = 0xf52f;
      local_78 = 0xf52f;
      local_74 = 0xf52f;
      local_84 = (code *)0x3000020;
      local_80 = 0x2600020;
      local_86 = 0xe4;
      break;
    case 0xae:
      uStack_5c = FUN_80022264(0xffffffe2,0x1e);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803e0970 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(0x1e,0x28);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803e0974 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0xffffffe2,0x1e);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803e0970 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_44 = FUN_80022264(0x1e,0x50);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803e0978 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      local_c8[2] = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x100200;
      local_86 = 0x88;
      break;
    case 0xaf:
      uStack_44 = FUN_80022264(0xffffffe2,0x1e);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803e097c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0a08);
      uStack_4c = FUN_80022264(0x1e,0x28);
      uStack_4c = uStack_4c ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803e0974 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e0a08);
      uStack_54 = FUN_80022264(0xffffffe2,0x1e);
      uStack_54 = uStack_54 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803e097c * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e0a08);
      uStack_5c = FUN_80022264(0x3c,0x50);
      uStack_5c = uStack_5c ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803e0980 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e0a08);
      local_c8[2] = 0x46;
      local_68 = 0x9b;
      local_84 = (code *)0x400000;
      local_80 = 8;
      local_86 = 0xe4;
    }
    local_84 = (code *)((uint)local_84 | param_4);
    if ((((uint)local_84 & 1) != 0) && (((uint)local_84 & 2) != 0)) {
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
    (**(code **)(*DAT_803dd6f8 + 8))(local_c8,0xffffffff,(int)uVar4,0);
  }
LAB_800bfab8:
  FUN_80286884();
  return;
}

