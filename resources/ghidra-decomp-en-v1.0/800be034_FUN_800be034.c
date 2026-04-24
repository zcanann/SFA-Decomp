// Function: FUN_800be034
// Entry: 800be034
// Size: 6160 bytes

void FUN_800be034(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5,int param_6)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined8 uVar5;
  int local_c8;
  undefined4 local_c4;
  int local_c0;
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
  double local_30;
  
  uVar5 = FUN_802860d4();
  iVar3 = (int)((ulonglong)uVar5 >> 0x20);
  iVar1 = FUN_8002b9ec();
  FLOAT_803db800 = FLOAT_803db800 + FLOAT_803dfcd8;
  if (FLOAT_803dfce0 < FLOAT_803db800) {
    FLOAT_803db800 = FLOAT_803dfcdc;
  }
  FLOAT_803db804 = FLOAT_803db804 + FLOAT_803dfce4;
  if (FLOAT_803dfce0 < FLOAT_803db804) {
    FLOAT_803db804 = FLOAT_803dfce8;
  }
  if (iVar3 == 0) {
    uVar2 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar2 = 0xffffffff;
        goto LAB_800bf82c;
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
    local_6a = (undefined)uVar5;
    local_98 = FLOAT_803dfcec;
    local_94 = FLOAT_803dfcec;
    local_90 = FLOAT_803dfcec;
    local_a4 = FLOAT_803dfcec;
    local_a0 = FLOAT_803dfcec;
    local_9c = FLOAT_803dfcec;
    local_8c = FLOAT_803dfcec;
    local_c0 = 0;
    local_c4 = 0xffffffff;
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
    local_c8 = iVar3;
    switch((int)uVar5) {
    case 0x84:
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803dfd18 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(4,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_a0 = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0xffffffd8,0x28);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_9c = FLOAT_803dfd1c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0x28,0x50);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfd20 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      local_c0 = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x1400211;
      local_86 = 0xdf;
      break;
    case 0x85:
      if (param_6 == 0) {
        uVar2 = 0;
        goto LAB_800bf82c;
      }
      local_98 = *(float *)(iVar1 + 0x18);
      local_94 = *(float *)(iVar1 + 0x1c);
      local_90 = *(float *)(iVar1 + 0x20);
      local_8c = FLOAT_803dfd24;
      local_c0 = 0x28;
      local_68 = 0xff;
      local_84 = (code *)0x110;
      local_86 = param_3[2] + 0x170;
      break;
    default:
      uVar2 = 0xffffffff;
      goto LAB_800bf82c;
    case 0x8a:
      local_98 = FLOAT_803dfd28;
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_a4 = FLOAT_803dfd2c;
      uStack68 = FUN_800221a0(0x28,0x50);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfd30 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      local_c0 = 0x10e;
      local_67 = '\x10';
      local_68 = 0xf;
      local_84 = (code *)0x2000011;
      local_86 = 0x5f;
      break;
    case 0x8b:
      uStack52 = FUN_800221a0(0xffffff88,0x78);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_98 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffff88,0x78);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0xffffff88,0x78);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803dfd34 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(4,10);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfd34 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      uStack92 = FUN_800221a0(0xffffffd8,0x28);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803dfd34 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfd88);
      uVar4 = FUN_800221a0(0x28,0x50);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_8c = FLOAT_803dfd38 * (float)(local_30 - DOUBLE_803dfd88);
      local_c0 = 0x46;
      local_68 = 0xff;
      local_c4 = 0x378;
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
      uVar4 = FUN_800221a0(0xffffffd8,0x28);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803dfd3c * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfd3c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfd3c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_8c = FLOAT_803dfd3c;
      local_c0 = 0x50;
      local_68 = 0xff;
      local_84 = (code *)0x100110;
      local_86 = 0x30;
      break;
    case 0x8f:
      uVar4 = FUN_800221a0(0xfffffffa,6);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_98 = (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xfffffffa,6);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xfffffffa,6);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0xffffffd8,0x28);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfd1c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0xffffffd8,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803dfd1c * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(0xffffffd8,0x28);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803dfd1c * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      iVar3 = FUN_800221a0(0,0xc);
      if (iVar3 == 0) {
        uVar4 = FUN_800221a0(0xf,0x1e);
        local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_8c = FLOAT_803dfd40 * (float)(local_30 - DOUBLE_803dfd88);
        local_68 = 0x5f;
      }
      else {
        uVar4 = FUN_800221a0(0xf,0x1e);
        local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_8c = FLOAT_803dfd44 * (float)(local_30 - DOUBLE_803dfd88);
        local_68 = 0xff;
      }
      local_c0 = 0x1e;
      local_84 = (code *)0x400108;
      local_86 = 0x33;
      break;
    case 0x9a:
      local_98 = FLOAT_803dfd48;
      uVar4 = FUN_800221a0(0xffffffbe,0x42);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_94 = FLOAT_803dfd4c + (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xffffffbe,0x42);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(1,10);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(0x50,0x78);
      local_68 = 0xff;
      local_84 = (code *)0x100210;
      local_86 = 0x125;
      local_67 = '\x05';
      break;
    case 0x9b:
      uVar4 = FUN_800221a0(0xffffffbe,0x42);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_98 = (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0,0x42);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dfd4c - (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffffa0,0x60);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0,0x28);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a0 = FLOAT_803dfd50 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(10,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfd54 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(0,0x1e);
      local_c0 = local_c0 + 0x1e;
      local_68 = 0xff;
      local_84 = (code *)0x100200;
      local_86 = 0x125;
      break;
    case 0x9c:
      uVar4 = FUN_800221a0(0xffffffd8,0x28);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803dfd50 * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfd50 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfd50 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_8c = FLOAT_803dfd58;
      local_c0 = 0x1e;
      local_68 = 0xff;
      local_84 = (code *)0x110;
      local_86 = 0xdd;
      break;
    case 0x9f:
      uVar4 = FUN_800221a0(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803dfd5c * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfd5c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfd5c * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_8c = FLOAT_803dfd54;
      local_c0 = FUN_800221a0(0x23,0x4b);
      local_84 = (code *)0x81480000;
      local_80 = 0x410800;
      local_86 = 0x167;
      break;
    case 0xa0:
      if (param_3 == (undefined2 *)0x0) {
        DAT_8039c374 = FLOAT_803dfcec;
        DAT_8039c378 = FLOAT_803dfcec;
        DAT_8039c37c = FLOAT_803dfcec;
        DAT_8039c370 = FLOAT_803dfce0;
        DAT_8039c368 = 0;
        DAT_8039c36a = 0;
        DAT_8039c36c = 0;
        param_3 = &DAT_8039c368;
      }
      uVar4 = FUN_800221a0(0xffffffec,0xfffffff6);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_98 = FLOAT_803dfcdc * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xfffffff6,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_94 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xfffffff6,0);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_68 = 0xff;
      if (param_3 != (undefined2 *)0x0) {
        local_98 = local_98 + *(float *)(param_3 + 6);
        local_94 = local_94 + *(float *)(param_3 + 8);
        local_90 = local_90 + *(float *)(param_3 + 10);
        if (FLOAT_803dfce0 == *(float *)(param_3 + 4)) {
          local_68 = 0xff;
        }
        else {
          iVar3 = (int)(FLOAT_803dfd60 * *(float *)(param_3 + 4));
          local_30 = (double)(longlong)iVar3;
          local_68 = (undefined)iVar3;
        }
      }
      uVar4 = FUN_800221a0(10,0x14);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_8c = FLOAT_803dfd64 * (float)(local_30 - DOUBLE_803dfd88);
      local_c0 = 0x2d;
      local_84 = (code *)0x200;
      local_86 = 0x125;
      local_67 = FUN_800221a0(0,0x14);
      local_67 = local_67 + '\x04';
      break;
    case 0xa1:
      uVar4 = FUN_800221a0(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a0 = FLOAT_803dfd68 * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(100,0x96);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a4 = FLOAT_803dfd6c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803dfd70 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0xffffff9c,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_94 = FLOAT_803dfd70 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0x32,200);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_8c = FLOAT_803dfd74 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      local_c0 = 0x96;
      local_86 = 0xc10;
      local_84 = FUN_80080100;
      local_80 = 0x4020020;
      local_68 = FUN_800221a0(0x7f,0xff);
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
        uVar4 = FUN_800221a0(100,0x78);
        local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_9c = FLOAT_803dfd78 * (float)(local_30 - DOUBLE_803dfd88);
        uStack52 = FUN_800221a0(0x3c,0x50);
        uStack52 = uStack52 ^ 0x80000000;
        local_38 = 0x43300000;
        local_8c = FLOAT_803dfd7c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88)
        ;
        iVar3 = FUN_800221a0(0,5);
        local_c0 = iVar3 + (short)param_3[3] + 7;
        local_86 = 0x185;
        local_84 = (code *)0xc0080004;
        local_80 = 0x4420800;
      }
      break;
    case 0xa7:
      uVar4 = FUN_800221a0(0xffffff9c,100);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_a4 = FLOAT_803dfd80 * (float)(local_30 - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(0xffffff9c,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_a0 = FLOAT_803dfd80 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      uStack60 = FUN_800221a0(0xffffff9c,100);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_9c = FLOAT_803dfd80 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0x23,0x32);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfd20 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(10,0x28);
      local_c0 = local_c0 + 10;
      local_86 = 0xc13;
      local_84 = (code *)0x81080010;
      local_80 = 0x482800;
      break;
    case 0xa8:
      local_8c = FLOAT_803dfcdc;
      local_c0 = 0xe;
      local_84 = (code *)0x480100;
      local_80 = 0x4000800;
      local_86 = 0x5fd;
      local_68 = 100;
      break;
    case 0xa9:
      if (param_3 == (undefined2 *)0x0) {
        uVar4 = FUN_800221a0(0x4b,100);
        local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_8c = FLOAT_803dfd20 * (float)(local_30 - DOUBLE_803dfd88);
      }
      else {
        uVar4 = FUN_800221a0(0x4b,100);
        local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
        local_8c = *(float *)(param_3 + 4) * FLOAT_803dfd20 * (float)(local_30 - DOUBLE_803dfd88);
      }
      local_c0 = 1;
      local_84 = (code *)0x80010;
      local_80 = 0x800;
      local_86 = 0xc7e;
      local_68 = 0x96;
      break;
    case 0xaa:
      uVar4 = FUN_800221a0(0x96,200);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_8c = FLOAT_803dfd84 * (float)(local_30 - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(0xf,0x19);
      local_86 = 0x185;
      local_84 = (code *)0x80180200;
      local_80 = 0x4000000;
      local_68 = 0x96;
      break;
    case 0xab:
      uVar4 = FUN_800221a0(100,0x96);
      local_30 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
      local_8c = FLOAT_803dfd84 * (float)(local_30 - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(0x19,0x2d);
      local_86 = 0x185;
      local_84 = (code *)0x80180210;
      local_80 = 0x4000800;
      break;
    case 0xac:
      uStack60 = FUN_800221a0(0xffffffce,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_98 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_94 = FLOAT_803dfcec;
      uStack68 = FUN_800221a0(0xffffffce,0x32);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_90 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0xfffffff8,8);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a4 = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(9,0xc);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfd10 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      uStack92 = FUN_800221a0(0xfffffff8,8);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_9c = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfd88);
      uStack52 = FUN_800221a0(10,0xf);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dfd14 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfd88);
      local_c0 = FUN_800221a0(0,0x14);
      local_c0 = local_c0 + 0x5f;
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
      uStack68 = FUN_800221a0(0xffffffe2,0x1e);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(6,0x16);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803dfd08 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(0xffffffe2,0x1e);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803dfd04 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      uStack92 = FUN_800221a0(0xffffffce,0x32);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_98 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfd88);
      local_94 = FLOAT_803dfcec;
      uStack60 = FUN_800221a0(0xffffffce,0x32);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_90 = FLOAT_803dfcdc * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfd88);
      local_8c = FLOAT_803dfd0c;
      local_c0 = 0x91;
      local_68 = 0xff;
      local_70 = 0xffff;
      local_6e = FUN_800221a0(0,10000);
      local_6e = local_6e + 0x3caf;
      local_6c = 0x3caf;
      local_7c = 0xf52f;
      local_78 = 0xf52f;
      local_74 = 0xf52f;
      local_84 = (code *)0x3000020;
      local_80 = 0x2600020;
      local_86 = 0xe4;
      break;
    case 0xae:
      uStack92 = FUN_800221a0(0xffffffe2,0x1e);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_a4 = FLOAT_803dfcf0 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(0x1e,0x28);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_9c = FLOAT_803dfcf4 * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0xffffffe2,0x1e);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_a0 = FLOAT_803dfcf0 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack68 = FUN_800221a0(0x1e,0x50);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_8c = FLOAT_803dfcf8 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      local_c0 = 0x46;
      local_68 = 0xff;
      local_84 = (code *)0x100200;
      local_86 = 0x88;
      break;
    case 0xaf:
      uStack68 = FUN_800221a0(0xffffffe2,0x1e);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_a4 = FLOAT_803dfcfc * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfd88);
      uStack76 = FUN_800221a0(0x1e,0x28);
      uStack76 = uStack76 ^ 0x80000000;
      local_50 = 0x43300000;
      local_9c = FLOAT_803dfcf4 * (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803dfd88);
      uStack84 = FUN_800221a0(0xffffffe2,0x1e);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      local_a0 = FLOAT_803dfcfc * (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803dfd88);
      uStack92 = FUN_800221a0(0x3c,0x50);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      local_8c = FLOAT_803dfd00 * (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803dfd88);
      local_c0 = 0x46;
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
    uVar2 = (**(code **)(*DAT_803dca78 + 8))(&local_c8,0xffffffff,(int)uVar5,0);
  }
LAB_800bf82c:
  FUN_80286120(uVar2);
  return;
}

