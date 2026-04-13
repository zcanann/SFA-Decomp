// Function: FUN_800b9008
// Entry: 800b9008
// Size: 13204 bytes

void FUN_800b9008(undefined4 param_1,undefined4 param_2,ushort *param_3,uint param_4,
                 undefined param_5)

{
  int iVar1;
  uint uVar2;
  undefined8 uVar3;
  ushort local_c8;
  undefined2 local_c6;
  undefined2 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  int local_b0 [3];
  ushort local_a4;
  ushort local_a2;
  ushort local_a0;
  undefined4 local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  undefined2 local_70;
  undefined2 local_6e;
  code *local_6c;
  uint local_68;
  uint local_64;
  int local_60;
  int local_5c;
  ushort local_58;
  undefined2 local_56;
  undefined2 local_54;
  undefined local_52;
  char local_50;
  undefined local_4f;
  undefined local_4e;
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
  
  uVar3 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  FLOAT_803dc430 = FLOAT_803dc430 + FLOAT_803e0708;
  if (FLOAT_803e0710 < FLOAT_803dc430) {
    FLOAT_803dc430 = FLOAT_803e070c;
  }
  FLOAT_803dc434 = FLOAT_803dc434 + FLOAT_803e0714;
  if (FLOAT_803e0710 < FLOAT_803dc434) {
    FLOAT_803dc434 = FLOAT_803e0718;
  }
  if (iVar1 != 0) {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_9c = *(undefined4 *)(param_3 + 4);
      local_a0 = param_3[2];
      local_a2 = param_3[1];
      local_a4 = *param_3;
      local_4e = param_5;
    }
    local_6c = (code *)0x0;
    local_68 = 0;
    local_52 = (undefined)uVar3;
    local_80 = FLOAT_803e071c;
    local_7c = FLOAT_803e071c;
    local_78 = FLOAT_803e071c;
    local_8c = FLOAT_803e071c;
    local_88 = FLOAT_803e071c;
    local_84 = FLOAT_803e071c;
    local_74 = FLOAT_803e071c;
    local_b0[2] = 0;
    local_b0[1] = 0xffffffff;
    local_50 = -1;
    local_4f = 0;
    local_6e = 0;
    local_58 = 0xffff;
    local_56 = 0xffff;
    local_54 = 0xffff;
    local_64 = 0xffff;
    local_60 = 0xffff;
    local_5c = 0xffff;
    local_70 = 0;
    local_b0[0] = iVar1;
    switch((int)uVar3) {
    case 400:
      uStack_1c = FUN_80022264(1,5);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0750 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(10,0x14);
      local_68 = 2;
      local_4f = 0;
      local_6e = 0xdf;
      break;
    case 0x191:
      uStack_1c = FUN_80022264(0xfffffff8,8);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x50);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xfffffff8,8);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xfffffffd,3);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0754 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0708;
      local_b0[2] = 100;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (code *)0x110;
      local_6e = 0xde;
      break;
    case 0x192:
      uStack_1c = FUN_80022264(0xffffff62,0x9e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x78);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffff30,0xd0);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xfffffffd,3);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0758 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_74 = FLOAT_803e075c;
      local_b0[2] = 200;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (code *)0x80080112;
      local_6e = 0x1dd;
      break;
    case 0x193:
      uStack_1c = FUN_80022264(0xffffff62,0x9e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x78);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffc6,0x3a);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xfffffffd,3);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0754 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_74 = FLOAT_803e075c;
      local_b0[2] = 100;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (code *)0x80080112;
      local_6e = 0xde;
      break;
    case 0x194:
      uStack_1c = FUN_80022264(0xffffffc6,0x3a);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x78);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffc6,0x3a);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xfffffffb,5);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(0,0x50);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      uStack_44 = FUN_80022264(0xfffffffb,5);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0760;
      local_b0[2] = 0x96;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (code *)0x80480110;
      local_68 = 8;
      local_6e = 0xde;
      break;
    case 0x195:
      local_74 = FLOAT_803e0764;
      local_b0[2] = 0x14;
      local_50 = -0x65;
      local_4f = 0x10;
      local_6c = (code *)0x80480214;
      local_6e = 0xde;
      break;
    case 0x196:
      uStack_1c = FUN_80022264(0xffffffe2,0x1e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffe2,0x1e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xfffffff1,0xf);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0768 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xf,0x23);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e076c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(0xfffffff1,0xf);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0768 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0770;
      local_b0[2] = 0x78;
      local_50 = -1;
      local_4f = 0x10;
      local_58 = 0xffff;
      local_56 = 0xffff;
      local_54 = 0x8acf;
      local_64 = 45000;
      local_60 = 15000;
      local_5c = 0x5dc;
      local_6c = (code *)0x81080200;
      local_68 = 0x24;
      local_6e = 0x1dd;
      break;
    case 0x197:
      uStack_1c = FUN_80022264(0xffffffe2,0x1e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffe2,0x1e);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xfffffff1,0xf);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0774 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xf,0x23);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0778 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(0xfffffff1,0xf);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0774 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0730;
      local_b0[2] = 0x50;
      local_50 = -1;
      local_4f = 0x10;
      local_58 = 0xf82f;
      local_56 = 0xf447;
      local_54 = 0xffff;
      local_64 = 43000;
      local_60 = 0;
      local_5c = 0;
      local_6c = FUN_80080610;
      local_68 = 0x24;
      local_6e = 0x1de;
      break;
    case 0x198:
      uStack_1c = FUN_80022264(0,0x3c);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803e077c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0780;
      local_b0[2] = 0x1e;
      local_50 = -1;
      local_6c = (code *)0x8100200;
      local_6e = 0x91;
      break;
    case 0x199:
      uStack_1c = FUN_80022264(0,0x32);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0788 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850)
                 + FLOAT_803e0784;
      local_b0[2] = 0;
      uVar2 = FUN_80022264(0,0x37);
      local_50 = (char)uVar2 + -0x38;
      local_4f = 0;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_6e = 0x156;
      }
      else if (uVar2 == 1) {
        local_6e = 0x157;
      }
      else if (uVar2 == 2) {
        local_6e = 0xc0e;
      }
      local_6c = (code *)0x80011;
      local_68 = 2;
      break;
    case 0x19a:
      uStack_1c = FUN_80022264(0,0x32);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0788 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850)
                 + FLOAT_803e078c;
      local_b0[2] = 0xc;
      local_50 = '7';
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (code *)0x180011;
      local_68 = 2;
      break;
    case 0x19b:
      uStack_1c = FUN_80022264(0,0x32);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e0788 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850)
                 + FLOAT_803e078c;
      local_b0[2] = 0;
      local_50 = -0x65;
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (code *)0x80011;
      local_68 = 2;
      break;
    case 0x19c:
      local_74 = FLOAT_803e0790;
      local_b0[2] = 2;
      local_50 = -0x65;
      local_4f = 0;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_6e = 0x156;
      }
      else if (uVar2 == 1) {
        local_6e = 0x157;
      }
      else if (uVar2 == 2) {
        local_6e = 0xc0e;
      }
      local_6c = (code *)0x480001;
      break;
    case 0x19d:
      local_74 = FLOAT_803e0794;
      local_b0[2] = 0xf;
      local_50 = -0x65;
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (code *)0x180201;
      break;
    default:
      goto LAB_800bc384;
    case 0x19f:
      uStack_1c = FUN_80022264(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0x4b,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e0798 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(0x37,0x4b);
      local_50 = '7';
      local_6e = 0xdb;
      local_6c = (code *)0x80080000;
      local_68 = 0x4402800;
      break;
    case 0x1a0:
      uStack_1c = FUN_80022264(0x4b,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e079c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_50 = '7';
      local_b0[2] = 0xf;
      local_4f = 0x10;
      local_6e = 0xdb;
      local_6c = (code *)0x80100;
      local_68 = 0x4000800;
      break;
    case 0x1a1:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e07a0 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e07a0 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(10,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e076c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xffffffec,0x14);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(10,0x14);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e07a4 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e07a8;
      local_b0[2] = FUN_80022264(0x28,0x50);
      local_50 = -1;
      local_b0[1] = 0x1a2;
      local_6c = (code *)0x2000104;
      local_68 = 0x200;
      local_6e = 0x7b;
      break;
    case 0x1a2:
      local_74 = FLOAT_803e07a8;
      local_b0[2] = 0x3c;
      local_50 = -1;
      local_6c = (code *)0x2000104;
      local_68 = 0x200;
      local_6e = 0x7b;
      break;
    case 0x1a3:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0,0x1e);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850)
                 + FLOAT_803e07a0;
      uStack_34 = FUN_80022264(1,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07ac * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(0x5a,0x8c);
      local_6c = (code *)0x80500209;
      local_4f = 0;
      local_6e = 0x23b;
      break;
    case 0x1a4:
      if (param_3 == (ushort *)0x0) {
        uStack_1c = FUN_80022264(0xfffffff6,10);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_80 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
        local_7c = FLOAT_803e07b4;
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_78 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      }
      else {
        local_80 = *(float *)(param_3 + 6);
        local_7c = FLOAT_803e07b0 + *(float *)(param_3 + 8);
        local_78 = *(float *)(param_3 + 10);
      }
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e07b8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07c0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850)
                 + FLOAT_803e07bc;
      local_b0[2] = FUN_80022264(0xbe,0xfa);
      local_50 = -0x65;
      local_b0[1] = 0x281;
      local_6c = (code *)0x81488000;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_6e = 0x208;
      }
      else if (uVar2 == 1) {
        local_6e = 0x209;
      }
      else if (uVar2 == 2) {
        local_6e = 0x20a;
      }
      break;
    case 0x1a5:
      if (param_3 == (ushort *)0x0) {
        uStack_1c = FUN_80022264(0,0x14);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_88 = FLOAT_803e07c4 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      }
      else {
        if (*(float *)(param_3 + 4) <= FLOAT_803e0730) {
          *(float *)(param_3 + 4) = FLOAT_803e0730;
        }
        local_88 = -*(float *)(param_3 + 4);
      }
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e07c8 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803e07c8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(2,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e07cc * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(0x3c,0x46);
      local_50 = -1;
      local_6c = (code *)0x80480108;
      local_6e = 0xc13;
      break;
    case 0x1a6:
      if (param_3 == (ushort *)0x0) {
        uStack_1c = FUN_80022264(0xfffffff6,10);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_80 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
        local_7c = FLOAT_803e07b4;
        uStack_24 = FUN_80022264(0xfffffff6,10);
        uStack_24 = uStack_24 ^ 0x80000000;
        local_28 = 0x43300000;
        local_78 = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      }
      else {
        local_80 = *(float *)(param_3 + 6);
        local_7c = *(float *)(param_3 + 8);
        local_78 = *(float *)(param_3 + 10);
      }
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e07b8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0,10);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07c0 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850)
                 + FLOAT_803e07bc;
      local_b0[2] = FUN_80022264(0xbe,0xfa);
      local_50 = -0x65;
      local_b0[1] = 0x281;
      local_6c = (code *)0x81488000;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_6e = 0x208;
      }
      else if (uVar2 == 1) {
        local_6e = 0x209;
      }
      else if (uVar2 == 2) {
        local_6e = 0x20a;
      }
      local_58 = 0x3200;
      local_56 = 0x3200;
      local_54 = 0x7800;
      local_64 = 0x3200;
      local_60 = 0x3200;
      local_5c = 0x7800;
      local_68 = 0x20;
      break;
    case 0x1a7:
      local_74 = FLOAT_803e07d0;
      local_b0[2] = FUN_80022264(0,0xfa);
      local_b0[2] = local_b0[2] + 0x96;
      local_4f = 0;
      local_b0[1] = 0x1a8;
      local_6c = (code *)0x80490008;
      local_6e = 0x167;
      break;
    case 0x1a8:
      local_74 = FLOAT_803e07d4;
      local_b0[2] = 10;
      local_4f = 0;
      local_50 = -1;
      local_6c = (code *)0x80480100;
      local_6e = 0x167;
      break;
    case 0x1a9:
      uVar2 = FUN_80022264(0,0x50);
      if (uVar2 == 0) {
        local_b0[2] = 0xf0;
        local_8c = FLOAT_803e07d8;
      }
      else {
        local_b0[2] = 0x78;
        local_8c = FLOAT_803e07dc;
      }
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      uVar2 = FUN_80022264(0,0xffff);
      local_c4 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c6 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_8c);
      local_74 = FLOAT_803e073c;
      local_4f = 0x10;
      local_50 = -1;
      local_6c = (code *)0x80100;
      local_6e = 0xdf;
      break;
    case 0x1aa:
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      uStack_1c = FUN_80022264(0,0x640);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0708 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850)
                 + FLOAT_803e07f0;
      FUN_80021b8c(param_3,&local_8c);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 == 0) {
        local_74 = FLOAT_803e0778;
        local_50 = -0x65;
      }
      else {
        local_74 = FLOAT_803e073c;
        local_50 = -1;
      }
      local_b0[2] = 0xf0;
      local_4f = 0x10;
      local_6c = (code *)0x80480200;
      local_6e = 0xdf;
      break;
    case 0x1ab:
      local_80 = FLOAT_803e0808;
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      uVar2 = FUN_80022264(0,0xffff);
      local_c4 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c6 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_80);
      local_8c = local_80 / FLOAT_803e07b0;
      local_88 = local_7c / FLOAT_803e07b0;
      local_84 = local_78 / FLOAT_803e07b0;
      uStack_1c = FUN_80022264(200,1000);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e080c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(100,200);
      local_50 = (char)uVar2 + '7';
      local_b0[2] = 0x50;
      local_4f = 0x10;
      local_6c = (code *)0x80480504;
      local_6e = 0x30;
      break;
    case 0x1ac:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e0810 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e0810 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e0810 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(500,1000);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e0814 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(0x9b,0xff);
      local_50 = (char)uVar2;
      local_b0[2] = FUN_80022264(0,0x28);
      local_b0[2] = local_b0[2] + 0x1e;
      local_4f = 0;
      local_6c = (code *)0x80180104;
      local_6e = 0x60;
      local_64 = 0x6400;
      uVar2 = FUN_80022264(0,0x55);
      local_60 = (uVar2 + 0xaa) * 0x100;
      uVar2 = FUN_80022264(0,0x37);
      local_5c = (uVar2 + 200) * 0x100;
      local_58 = 0xff00;
      local_56 = 0xff00;
      local_54 = 0xff00;
      local_68 = 0x20;
      break;
    case 0x1ad:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(200,0x5dc);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07ec * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(0,0x28);
      local_b0[2] = local_b0[2] + 0x1e;
      uVar2 = FUN_80022264(0xb4,200);
      local_50 = (char)uVar2 + '7';
      local_4f = 0;
      local_6c = (code *)0x80580104;
      local_6e = 0xc22;
      local_64 = 0xc800;
      uVar2 = FUN_80022264(0,0x37);
      local_60 = (uVar2 + 200) * 0x100;
      uVar2 = FUN_80022264(0,0x19);
      local_5c = (uVar2 + 0xe6) * 0x100;
      local_58 = 0xff00;
      local_56 = 0xff00;
      local_54 = 0xff00;
      local_68 = 0x20;
      break;
    case 0x1ae:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(200,1000);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07f4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(100,200);
      local_50 = (char)uVar2 + '7';
      local_b0[2] = FUN_80022264(0,0x28);
      local_b0[2] = local_b0[2] + 0x3c;
      local_4f = 0x10;
      local_6c = (code *)0x80480104;
      local_68 = 8;
      local_6e = 0x30;
      break;
    case 0x1af:
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      uStack_1c = FUN_80022264(0xffffffff,1);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffff,1);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffff,1);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(400,500);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07f4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_50 = -1;
      local_b0[2] = FUN_80022264(0,0x14);
      local_b0[2] = local_b0[2] + 0xa0;
      local_4f = 0x10;
      local_6c = FUN_80080404;
      local_6e = 0x5c;
      local_58 = 0xfffe;
      local_56 = 0x8ace;
      local_54 = 0;
      local_64 = 20000;
      local_60 = 40000;
      local_5c = 0xfffe;
      local_68 = 0x20;
      break;
    case 0x1b0:
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      local_74 = FLOAT_803e07fc;
      local_50 = -1;
      uVar2 = FUN_80022264(0,0xffff);
      local_a4 = (ushort)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_a2 = (ushort)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_a4 = (ushort)uVar2;
      local_98 = FLOAT_803e071c;
      local_94 = FLOAT_803e071c;
      local_90 = FLOAT_803e071c;
      local_b0[2] = 0xa0;
      local_4f = 0x10;
      local_6c = (code *)0x6100214;
      local_6e = 0x167;
      break;
    case 0x1b1:
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e07f8 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(1,5);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = *(float *)(param_3 + 6) *
                 FLOAT_803e0800 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_50 = -1;
      uVar2 = FUN_80022264(0,0xffff);
      local_a4 = (ushort)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_a2 = (ushort)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_a4 = (ushort)uVar2;
      local_98 = FLOAT_803e071c;
      local_94 = FLOAT_803e071c;
      local_90 = FLOAT_803e071c;
      local_b0[2] = 0xa0;
      local_4f = 0x10;
      local_6c = (code *)0x6100214;
      local_6e = 0x30;
      break;
    case 0x1b2:
      uStack_1c = FUN_80022264(0xffffffec,0x14);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffffec,0x14);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffffec,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0804 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(200,1000);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07f4 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(100,200);
      local_50 = (char)uVar2 + '7';
      local_b0[2] = FUN_80022264(0,0x28);
      local_b0[2] = local_b0[2] + 0x3c;
      local_4f = 0x10;
      local_6c = (code *)0x81480204;
      local_6e = 0x30;
      break;
    case 0x1b3:
      if (param_3 == (ushort *)0x0) goto LAB_800bc384;
      uStack_1c = FUN_80022264(0xfffffff1,0xf);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803e07e0 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850)
                 + FLOAT_803e0708;
      uStack_24 = FUN_80022264(0xfffffff1,0xf);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803e07e0 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850)
                 + FLOAT_803e0708;
      uStack_2c = FUN_80022264(0xfffffff1,0xf);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e07e0 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850)
                 + FLOAT_803e0708;
      local_7c = FLOAT_803e07e4;
      FUN_80021b8c(param_3,&local_8c);
      uStack_34 = FUN_80022264(0x14,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07e8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_50 = -1;
      local_b0[2] = 100;
      local_4f = 0x10;
      local_b0[1] = 0x1b4;
      local_6c = (code *)0x480200;
      local_68 = 0x100000;
      local_6e = 0x159;
      break;
    case 0x1b4:
      uStack_1c = FUN_80022264(0x14,0x1e);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e07ec * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_50 = '7';
      local_b0[2] = 0x14;
      local_4f = 0x10;
      local_6c = (code *)0x80201;
      local_68 = 2;
      local_6e = 0x159;
      break;
    case 0x1b6:
      if (param_3 == (ushort *)0x0) {
        uStack_1c = FUN_80022264(0xfffffffd,3);
        uStack_1c = uStack_1c ^ 0x80000000;
        local_20 = 0x43300000;
        local_88 = FLOAT_803e0758 *
                   (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      }
      else {
        local_88 = *(float *)(param_3 + 4);
      }
      local_74 = FLOAT_803e0780;
      local_b0[2] = 0x32;
      local_50 = -1;
      local_4f = 0x10;
      local_6c = (code *)0x88100200;
      local_6e = 0xc79;
      break;
    case 0x1b8:
      uStack_1c = FUN_80022264(0xfffff448,3000);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xfffff448,3000);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(1,4);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0848 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = 0x5a;
      local_50 = -1;
      local_6c = (code *)0xa100100;
      local_6e = 0x56;
      break;
    case 0x1b9:
      uStack_1c = FUN_80022264(0xfffffd44,700);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,1000);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803e081c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850)
                 + FLOAT_803e0818;
      local_7c = FLOAT_803e0820 * local_80;
      uStack_2c = FUN_80022264(0,10);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0828 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850)
                 + FLOAT_803e0824;
      local_88 = FLOAT_803e0820 * local_8c;
      uStack_34 = FUN_80022264(1,6);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e082c * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = 0xbe;
      local_50 = -1;
      local_6c = (code *)0x6000100;
      local_6e = 0x20;
      local_a0 = 0;
      local_a2 = 0x5fb4;
      local_a4 = 0xc001;
      local_98 = FLOAT_803e071c;
      local_94 = FLOAT_803e071c;
      local_90 = FLOAT_803e071c;
      break;
    case 0x1ba:
      local_7c = FLOAT_803e0840;
      uStack_1c = FUN_80022264(0xfffffc18,1000);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffff38,200);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      local_7c = FLOAT_803e0820 * local_80;
      uStack_2c = FUN_80022264(1,6);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0844 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = 0x82;
      local_50 = -1;
      local_6c = (code *)0x1000000;
      local_68 = 0x200000;
      local_6e = 0x20;
      break;
    case 0x1bc:
      uStack_1c = FUN_80022264(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffff9c,100);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e073c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0x4b,100);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e0798 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = FUN_80022264(0x8c,0xa5);
      local_50 = '7';
      local_6e = 0x167;
      local_6c = (code *)0x80000;
      local_68 = 0x4400000;
      break;
    case 0x1bd:
      uStack_1c = FUN_80022264(0x4b,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803e079c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_50 = '7';
      local_b0[2] = 0xf;
      local_4f = 0x10;
      local_6e = 100;
      local_6c = (code *)0x4080100;
      break;
    case 0x1bf:
      uStack_1c = FUN_80022264(0xffffff9c,100);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0,1000);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(0xffffff9c,100);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xffffffd8,0x28);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803e07b8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(500,600);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803e0830 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      uStack_44 = FUN_80022264(0xffffffd8,0x28);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803e07b8 * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0834;
      local_b0[2] = 0x15e;
      local_50 = -1;
      local_68 = 0x300020;
      local_6c = (code *)0x3008000;
      local_58 = 0xffff;
      local_56 = 0xffff;
      local_54 = 0xffff;
      local_64 = 0x63bf;
      local_60 = 0x9e7;
      local_5c = 1000;
      local_6e = 0x23b;
      break;
    case 0x1c0:
      uStack_1c = FUN_80022264(0xfffffd44,700);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xfffffd44,700);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(500,600);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0830 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0834;
      local_b0[2] = 0x96;
      local_50 = -1;
      local_68 = 0x200000;
      local_6c = (code *)0x2000200;
      local_6e = 0x23b;
      break;
    case 0x1c1:
      uStack_1c = FUN_80022264(0xfffffd44,700);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xfffffd44,700);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(500,600);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803e0838 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0x1e,0x32);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803e07c8 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      local_b0[2] = 0x96;
      local_50 = -0x65;
      local_68 = 0x20;
      local_6c = (code *)0x80100;
      uVar2 = FUN_80022264(0,30000);
      local_58 = (short)uVar2 + 0x63bf;
      uVar2 = FUN_80022264(1,3);
      local_56 = (undefined2)((int)(uint)local_58 / (int)uVar2);
      local_54 = 0;
      local_64 = FUN_80022264(0,10000);
      uVar2 = FUN_80022264(1,3);
      local_60 = (int)local_64 / (int)uVar2;
      local_5c = 0;
      local_6e = 0x60;
      break;
    case 0x1c2:
      uStack_1c = FUN_80022264(0xffffff38,200);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xffffff38,200);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(200,800);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803e0830 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        local_84 = local_84 * FLOAT_803e083c;
      }
      uStack_1c = FUN_80022264(200,800);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = FLOAT_803e0830 * (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uVar2 = FUN_80022264(0,1);
      if (uVar2 != 0) {
        local_88 = local_88 * FLOAT_803e083c;
      }
      local_74 = FLOAT_803e0744;
      local_b0[2] = FUN_80022264(0,0x1e);
      local_b0[2] = local_b0[2] + 0x14;
      local_50 = -1;
      local_68 = 0x200000;
      local_6c = (code *)0x2000200;
      local_6e = 0x23b;
      break;
    case 0x1c3:
      local_88 = FLOAT_803e070c;
      local_74 = FLOAT_803e0744;
      local_b0[2] = 0x3c;
      local_50 = -1;
      local_6c = (code *)0xa100110;
      local_6e = 0x23b;
      break;
    case 0x1c4:
      local_80 = FLOAT_803e0740;
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      uVar2 = FUN_80022264(0,0xffff);
      local_c4 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c6 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_80);
      local_74 = FLOAT_803e0744;
      local_b0[2] = 200;
      local_50 = -1;
      local_6c = (code *)0x480100;
      local_6e = 0x26c;
      break;
    case 0x1c5:
      local_80 = FLOAT_803e0738;
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      uVar2 = FUN_80022264(0,0xffff);
      local_c4 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c6 = (undefined2)uVar2;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_80);
      local_74 = FLOAT_803e073c;
      local_b0[2] = 200;
      local_50 = -1;
      local_6c = (code *)0x480100;
      local_6e = 0x33;
      break;
    case 0x1c6:
      uStack_1c = FUN_80022264(0,0x5a);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803e0748 + (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0xfffffff6,10);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      local_c4 = 0;
      local_c6 = 0;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_80);
      uStack_2c = FUN_80022264(1,0x14);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e074c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = 200;
      local_50 = -1;
      local_6c = (code *)0x480100;
      local_68 = 0x2000000;
      local_6e = 0x23c;
      break;
    case 0x1c7:
      uStack_2c = FUN_80022264(0xffffffe4,0x1c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xffffffe4,0x1c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(0xffffffe4,0x1c);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      uStack_44 = FUN_80022264(0xffffffba,0x46);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0850);
      uStack_24 = FUN_80022264(0x82,0xaa);
      uStack_24 = uStack_24 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e0850);
      uStack_1c = FUN_80022264(0xffffffba,0x46);
      uStack_1c = uStack_1c ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e0850);
      local_74 = FLOAT_803e0730;
      local_b0[2] = 400;
      local_50 = -1;
      local_58 = 0;
      local_56 = 0;
      local_54 = 0;
      local_64 = 0;
      local_60 = 0;
      local_5c = 0;
      local_6c = (code *)0x80480108;
      local_68 = 0x20;
      local_6e = 0x33;
      break;
    case 0x1c8:
      uStack_44 = FUN_80022264(0,100);
      uStack_44 = uStack_44 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803e070c * (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(0xffffffd8,0x28);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803e0720 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xffffffe2,0x1e);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = local_8c *
                 FLOAT_803e0720 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_2c = FUN_80022264(200,0x118);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e0724 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = 0x32;
      local_50 = -1;
      local_6c = (code *)0x80118;
      local_68 = 8;
      local_6e = 0x566;
      break;
    case 0x1c9:
      local_78 = FLOAT_803e0728;
      local_bc = FLOAT_803e071c;
      local_b8 = FLOAT_803e071c;
      local_b4 = FLOAT_803e071c;
      local_c0 = FLOAT_803e0710;
      local_c4 = 0;
      local_c6 = 0;
      uVar2 = FUN_80022264(0,0xffff);
      local_c8 = (ushort)uVar2;
      FUN_80021b8c(&local_c8,&local_80);
      uStack_2c = FUN_80022264(200,0x118);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803e072c * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      local_b0[2] = 0x14;
      local_50 = -0x1f;
      local_6c = (code *)0x400000;
      local_6e = 0x4f9;
      break;
    case 0x1ca:
      uStack_2c = FUN_80022264(0xffffffe4,0x1c);
      uStack_2c = uStack_2c ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e0850);
      uStack_34 = FUN_80022264(0xffffffe4,0x1c);
      uStack_34 = uStack_34 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803e0730 * (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e0850);
      uStack_3c = FUN_80022264(200,0x118);
      uStack_3c = uStack_3c ^ 0x80000000;
      local_40 = 0x43300000;
      local_74 = FLOAT_803e0734 * (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e0850);
      local_b0[2] = 200;
      local_50 = -0x1f;
      local_6c = (code *)0x400110;
      uVar2 = FUN_80022264(0,2);
      if (uVar2 == 0) {
        local_68 = local_68 | 0x100;
      }
      else {
        local_68 = local_68 | 0x400;
      }
      local_6e = 0x4f9;
    }
    local_6c = (code *)((uint)local_6c | param_4);
    if ((((uint)local_6c & 1) != 0) && (((uint)local_6c & 2) != 0)) {
      local_6c = (code *)((uint)local_6c ^ 2);
    }
    if (((uint)local_6c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b0[0] != 0) {
          local_80 = local_80 + *(float *)(local_b0[0] + 0x18);
          local_7c = local_7c + *(float *)(local_b0[0] + 0x1c);
          local_78 = local_78 + *(float *)(local_b0[0] + 0x20);
        }
      }
      else {
        local_80 = local_80 + local_98;
        local_7c = local_7c + local_94;
        local_78 = local_78 + local_90;
      }
    }
    (**(code **)(*DAT_803dd6f8 + 8))(local_b0,0xffffffff,(int)uVar3,0);
  }
LAB_800bc384:
  FUN_80286888();
  return;
}

