// Function: FUN_800b8d7c
// Entry: 800b8d7c
// Size: 13204 bytes

void FUN_800b8d7c(undefined4 param_1,undefined4 param_2,undefined2 *param_3,uint param_4,
                 undefined param_5)

{
  undefined4 uVar1;
  int iVar2;
  short sVar3;
  undefined8 uVar4;
  undefined2 local_c8;
  undefined2 local_c6;
  undefined2 local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  int local_b0;
  undefined4 local_ac;
  int local_a8;
  undefined2 local_a4;
  undefined2 local_a2;
  undefined2 local_a0;
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
  undefined *local_6c;
  uint local_68;
  int local_64;
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
  
  uVar4 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  FLOAT_803db7d0 = FLOAT_803db7d0 + FLOAT_803dfa88;
  if (FLOAT_803dfa90 < FLOAT_803db7d0) {
    FLOAT_803db7d0 = FLOAT_803dfa8c;
  }
  FLOAT_803db7d4 = FLOAT_803db7d4 + FLOAT_803dfa94;
  if (FLOAT_803dfa90 < FLOAT_803db7d4) {
    FLOAT_803db7d4 = FLOAT_803dfa98;
  }
  if (iVar2 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    if ((param_4 & 0x200000) != 0) {
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      local_98 = *(float *)(param_3 + 6);
      local_94 = *(float *)(param_3 + 8);
      local_90 = *(float *)(param_3 + 10);
      local_9c = *(undefined4 *)(param_3 + 4);
      local_a0 = param_3[2];
      local_a2 = param_3[1];
      local_a4 = *param_3;
      local_4e = param_5;
    }
    local_6c = (undefined *)0x0;
    local_68 = 0;
    local_52 = (undefined)uVar4;
    local_80 = FLOAT_803dfa9c;
    local_7c = FLOAT_803dfa9c;
    local_78 = FLOAT_803dfa9c;
    local_8c = FLOAT_803dfa9c;
    local_88 = FLOAT_803dfa9c;
    local_84 = FLOAT_803dfa9c;
    local_74 = FLOAT_803dfa9c;
    local_a8 = 0;
    local_ac = 0xffffffff;
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
    local_b0 = iVar2;
    switch((int)uVar4) {
    case 400:
      uStack28 = FUN_800221a0(1,5);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfad0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(10,0x14);
      local_68 = 2;
      local_4f = 0;
      local_6e = 0xdf;
      break;
    case 0x191:
      uStack28 = FUN_800221a0(0xfffffff8,8);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x50);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xfffffff8,8);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xfffffffd,3);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfad4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfa88;
      local_a8 = 100;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (undefined *)0x110;
      local_6e = 0xde;
      break;
    case 0x192:
      uStack28 = FUN_800221a0(0xffffff62,0x9e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x78);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffff30,0xd0);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xfffffffd,3);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfad8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfadc;
      local_a8 = 200;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (undefined *)0x80080112;
      local_6e = 0x1dd;
      break;
    case 0x193:
      uStack28 = FUN_800221a0(0xffffff62,0x9e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x78);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffc6,0x3a);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xfffffffd,3);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfad4 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfadc;
      local_a8 = 100;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (undefined *)0x80080112;
      local_6e = 0xde;
      break;
    case 0x194:
      uStack28 = FUN_800221a0(0xffffffc6,0x3a);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x78);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffc6,0x3a);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xfffffffb,5);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(0,0x50);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      uStack68 = FUN_800221a0(0xfffffffb,5);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfae0;
      local_a8 = 0x96;
      local_50 = '}';
      local_4f = 0x10;
      local_6c = (undefined *)0x80480110;
      local_68 = 8;
      local_6e = 0xde;
      break;
    case 0x195:
      local_74 = FLOAT_803dfae4;
      local_a8 = 0x14;
      local_50 = -0x65;
      local_4f = 0x10;
      local_6c = (undefined *)0x80480214;
      local_6e = 0xde;
      break;
    case 0x196:
      uStack28 = FUN_800221a0(0xffffffe2,0x1e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffe2,0x1e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xfffffff1,0xf);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfae8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xf,0x23);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfaec * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(0xfffffff1,0xf);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfae8 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfaf0;
      local_a8 = 0x78;
      local_50 = -1;
      local_4f = 0x10;
      local_58 = 0xffff;
      local_56 = 0xffff;
      local_54 = 0x8acf;
      local_64 = 45000;
      local_60 = 15000;
      local_5c = 0x5dc;
      local_6c = (undefined *)0x81080200;
      local_68 = 0x24;
      local_6e = 0x1dd;
      break;
    case 0x197:
      uStack28 = FUN_800221a0(0xffffffe2,0x1e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffe2,0x1e);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xfffffff1,0xf);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfaf4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xf,0x23);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfaf8 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(0xfffffff1,0xf);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfaf4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfab0;
      local_a8 = 0x50;
      local_50 = -1;
      local_4f = 0x10;
      local_58 = 0xf82f;
      local_56 = 0xf447;
      local_54 = 0xffff;
      local_64 = 43000;
      local_60 = 0;
      local_5c = 0;
      local_6c = (undefined *)0x80080610;
      local_68 = 0x24;
      local_6e = 0x1de;
      break;
    case 0x198:
      uStack28 = FUN_800221a0(0,0x3c);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_7c = FLOAT_803dfafc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfb00;
      local_a8 = 0x1e;
      local_50 = -1;
      local_6c = (undefined *)0x8100200;
      local_6e = 0x91;
      break;
    case 0x199:
      uStack28 = FUN_800221a0(0,0x32);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb08 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb04;
      local_a8 = 0;
      local_50 = FUN_800221a0(0,0x37);
      local_50 = local_50 + -0x38;
      local_4f = 0;
      iVar2 = FUN_800221a0(0,2);
      if (iVar2 == 0) {
        local_6e = 0x156;
      }
      else if (iVar2 == 1) {
        local_6e = 0x157;
      }
      else if (iVar2 == 2) {
        local_6e = 0xc0e;
      }
      local_6c = (undefined *)0x80011;
      local_68 = 2;
      break;
    case 0x19a:
      uStack28 = FUN_800221a0(0,0x32);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb08 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb0c;
      local_a8 = 0xc;
      local_50 = '7';
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (undefined *)0x180011;
      local_68 = 2;
      break;
    case 0x19b:
      uStack28 = FUN_800221a0(0,0x32);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb08 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb0c;
      local_a8 = 0;
      local_50 = -0x65;
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (undefined *)0x80011;
      local_68 = 2;
      break;
    case 0x19c:
      local_74 = FLOAT_803dfb10;
      local_a8 = 2;
      local_50 = -0x65;
      local_4f = 0;
      iVar2 = FUN_800221a0(0,2);
      if (iVar2 == 0) {
        local_6e = 0x156;
      }
      else if (iVar2 == 1) {
        local_6e = 0x157;
      }
      else if (iVar2 == 2) {
        local_6e = 0xc0e;
      }
      local_6c = (undefined *)0x480001;
      break;
    case 0x19d:
      local_74 = FLOAT_803dfb14;
      local_a8 = 0xf;
      local_50 = -0x65;
      local_4f = 0;
      local_6e = 0x153;
      local_6c = (undefined *)0x180201;
      break;
    default:
      uVar1 = 0xffffffff;
      goto LAB_800bc0f8;
    case 0x19f:
      uStack28 = FUN_800221a0(0xffffff9c,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffff9c,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0x4b,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb18 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(0x37,0x4b);
      local_50 = '7';
      local_6e = 0xdb;
      local_6c = (undefined *)0x80080000;
      local_68 = 0x4402800;
      break;
    case 0x1a0:
      uStack28 = FUN_800221a0(0x4b,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb1c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_50 = '7';
      local_a8 = 0xf;
      local_4f = 0x10;
      local_6e = 0xdb;
      local_6c = (undefined *)0x80100;
      local_68 = 0x4000800;
      break;
    case 0x1a1:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfb20 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfb20 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(10,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfaec * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xffffffec,0x14);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(10,0x14);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dfb24 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfb28;
      local_a8 = FUN_800221a0(0x28,0x50);
      local_50 = -1;
      local_ac = 0x1a2;
      local_6c = (undefined *)0x2000104;
      local_68 = 0x200;
      local_6e = 0x7b;
      break;
    case 0x1a2:
      local_74 = FLOAT_803dfb28;
      local_a8 = 0x3c;
      local_50 = -1;
      local_6c = (undefined *)0x2000104;
      local_68 = 0x200;
      local_6e = 0x7b;
      break;
    case 0x1a3:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0,0x1e);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb20;
      uStack52 = FUN_800221a0(1,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb2c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(0x5a,0x8c);
      local_6c = (undefined *)0x80500209;
      local_4f = 0;
      local_6e = 0x23b;
      break;
    case 0x1a4:
      if (param_3 == (undefined2 *)0x0) {
        uStack28 = FUN_800221a0(0xfffffff6,10);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_80 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
        local_7c = FLOAT_803dfb34;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_78 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      }
      else {
        local_80 = *(float *)(param_3 + 6);
        local_7c = FLOAT_803dfb30 + *(float *)(param_3 + 8);
        local_78 = *(float *)(param_3 + 10);
      }
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfb38 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb40 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb3c;
      local_a8 = FUN_800221a0(0xbe,0xfa);
      local_50 = -0x65;
      local_ac = 0x281;
      local_6c = (undefined *)0x81488000;
      iVar2 = FUN_800221a0(0,2);
      if (iVar2 == 0) {
        local_6e = 0x208;
      }
      else if (iVar2 == 1) {
        local_6e = 0x209;
      }
      else if (iVar2 == 2) {
        local_6e = 0x20a;
      }
      break;
    case 0x1a5:
      if (param_3 == (undefined2 *)0x0) {
        uStack28 = FUN_800221a0(0,0x14);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_88 = FLOAT_803dfb44 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0)
        ;
      }
      else {
        if (*(float *)(param_3 + 4) <= FLOAT_803dfab0) {
          *(float *)(param_3 + 4) = FLOAT_803dfab0;
        }
        local_88 = -*(float *)(param_3 + 4);
      }
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfb48 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_84 = FLOAT_803dfb48 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(2,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfb4c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(0x3c,0x46);
      local_50 = -1;
      local_6c = (undefined *)0x80480108;
      local_6e = 0xc13;
      break;
    case 0x1a6:
      if (param_3 == (undefined2 *)0x0) {
        uStack28 = FUN_800221a0(0xfffffff6,10);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_80 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
        local_7c = FLOAT_803dfb34;
        uStack36 = FUN_800221a0(0xfffffff6,10);
        uStack36 = uStack36 ^ 0x80000000;
        local_28 = 0x43300000;
        local_78 = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      }
      else {
        local_80 = *(float *)(param_3 + 6);
        local_7c = *(float *)(param_3 + 8);
        local_78 = *(float *)(param_3 + 10);
      }
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfb38 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0,10);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb40 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb3c;
      local_a8 = FUN_800221a0(0xbe,0xfa);
      local_50 = -0x65;
      local_ac = 0x281;
      local_6c = (undefined *)0x81488000;
      iVar2 = FUN_800221a0(0,2);
      if (iVar2 == 0) {
        local_6e = 0x208;
      }
      else if (iVar2 == 1) {
        local_6e = 0x209;
      }
      else if (iVar2 == 2) {
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
      local_74 = FLOAT_803dfb50;
      local_a8 = FUN_800221a0(0,0xfa);
      local_a8 = local_a8 + 0x96;
      local_4f = 0;
      local_ac = 0x1a8;
      local_6c = (undefined *)0x80490008;
      local_6e = 0x167;
      break;
    case 0x1a8:
      local_74 = FLOAT_803dfb54;
      local_a8 = 10;
      local_4f = 0;
      local_50 = -1;
      local_6c = (undefined *)0x80480100;
      local_6e = 0x167;
      break;
    case 0x1a9:
      iVar2 = FUN_800221a0(0,0x50);
      if (iVar2 == 0) {
        local_a8 = 0xf0;
        local_8c = FLOAT_803dfb58;
      }
      else {
        local_a8 = 0x78;
        local_8c = FLOAT_803dfb5c;
      }
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = FUN_800221a0(0,0xffff);
      local_c6 = FUN_800221a0(0,0xffff);
      local_c8 = FUN_800221a0(0,0xffff);
      FUN_80021ac8(&local_c8,&local_8c);
      local_74 = FLOAT_803dfabc;
      local_4f = 0x10;
      local_50 = -1;
      local_6c = (undefined *)0x80100;
      local_6e = 0xdf;
      break;
    case 0x1aa:
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      uStack28 = FUN_800221a0(0,0x640);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfa88 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb70;
      FUN_80021ac8(param_3,&local_8c);
      iVar2 = FUN_800221a0(0,1);
      if (iVar2 == 0) {
        local_74 = FLOAT_803dfaf8;
        local_50 = -0x65;
      }
      else {
        local_74 = FLOAT_803dfabc;
        local_50 = -1;
      }
      local_a8 = 0xf0;
      local_4f = 0x10;
      local_6c = (undefined *)0x80480200;
      local_6e = 0xdf;
      break;
    case 0x1ab:
      local_80 = FLOAT_803dfb88;
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = FUN_800221a0(0);
      local_c6 = FUN_800221a0(0,0xffff);
      local_c8 = FUN_800221a0(0,0xffff);
      FUN_80021ac8(&local_c8,&local_80);
      local_8c = local_80 / FLOAT_803dfb30;
      local_88 = local_7c / FLOAT_803dfb30;
      local_84 = local_78 / FLOAT_803dfb30;
      uStack28 = FUN_800221a0(200,1000);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_50 = FUN_800221a0(100,200);
      local_50 = local_50 + '7';
      local_a8 = 0x50;
      local_4f = 0x10;
      local_6c = (undefined *)0x80480504;
      local_6e = 0x30;
      break;
    case 0x1ac:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfb90 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfb90 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dfb90 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(500,1000);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb94 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_50 = FUN_800221a0(0x9b,0xff);
      local_a8 = FUN_800221a0(0,0x28);
      local_a8 = local_a8 + 0x1e;
      local_4f = 0;
      local_6c = (undefined *)0x80180104;
      local_6e = 0x60;
      local_64 = 0x6400;
      iVar2 = FUN_800221a0(0,0x55);
      local_60 = (iVar2 + 0xaa) * 0x100;
      iVar2 = FUN_800221a0(0,0x37);
      local_5c = (iVar2 + 200) * 0x100;
      local_58 = 0xff00;
      local_56 = 0xff00;
      local_54 = 0xff00;
      local_68 = 0x20;
      break;
    case 0x1ad:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(200,0x5dc);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb6c * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(0,0x28);
      local_a8 = local_a8 + 0x1e;
      local_50 = FUN_800221a0(0xb4,200);
      local_50 = local_50 + '7';
      local_4f = 0;
      local_6c = (undefined *)0x80580104;
      local_6e = 0xc22;
      local_64 = 0xc800;
      iVar2 = FUN_800221a0(0,0x37);
      local_60 = (iVar2 + 200) * 0x100;
      iVar2 = FUN_800221a0(0,0x19);
      local_5c = (iVar2 + 0xe6) * 0x100;
      local_58 = 0xff00;
      local_56 = 0xff00;
      local_54 = 0xff00;
      local_68 = 0x20;
      break;
    case 0x1ae:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(200,1000);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb74 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_50 = FUN_800221a0(100,200);
      local_50 = local_50 + '7';
      local_a8 = FUN_800221a0(0,0x28);
      local_a8 = local_a8 + 0x3c;
      local_4f = 0x10;
      local_6c = (undefined *)0x80480104;
      local_68 = 8;
      local_6e = 0x30;
      break;
    case 0x1af:
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      uStack28 = FUN_800221a0(0xffffffff,1);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffff,1);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffff,1);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = *(float *)(param_3 + 6) *
                 (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(400,500);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb74 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_50 = -1;
      local_a8 = FUN_800221a0(0,0x14);
      local_a8 = local_a8 + 0xa0;
      local_4f = 0x10;
      local_6c = &LAB_80080404;
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
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfb7c;
      local_50 = -1;
      local_a4 = FUN_800221a0(0,0xffff);
      local_a2 = FUN_800221a0(0,0xffff);
      local_a4 = FUN_800221a0(0,0xffff);
      local_98 = FLOAT_803dfa9c;
      local_94 = FLOAT_803dfa9c;
      local_90 = FLOAT_803dfa9c;
      local_a8 = 0xa0;
      local_4f = 0x10;
      local_6c = (undefined *)0x6100214;
      local_6e = 0x167;
      break;
    case 0x1b1:
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfb78 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(1,5);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = *(float *)(param_3 + 6) *
                 FLOAT_803dfb80 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_50 = -1;
      local_a4 = FUN_800221a0(0,0xffff);
      local_a2 = FUN_800221a0(0,0xffff);
      local_a4 = FUN_800221a0(0,0xffff);
      local_98 = FLOAT_803dfa9c;
      local_94 = FLOAT_803dfa9c;
      local_90 = FLOAT_803dfa9c;
      local_a8 = 0xa0;
      local_4f = 0x10;
      local_6c = (undefined *)0x6100214;
      local_6e = 0x30;
      break;
    case 0x1b2:
      uStack28 = FUN_800221a0(0xffffffec,0x14);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffffec,0x14);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffffec,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfb84 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(200,1000);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb74 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_50 = FUN_800221a0(100,200);
      local_50 = local_50 + '7';
      local_a8 = FUN_800221a0(0,0x28);
      local_a8 = local_a8 + 0x3c;
      local_4f = 0x10;
      local_6c = (undefined *)0x81480204;
      local_6e = 0x30;
      break;
    case 0x1b3:
      if (param_3 == (undefined2 *)0x0) {
        uVar1 = 0xffffffff;
        goto LAB_800bc0f8;
      }
      uStack28 = FUN_800221a0(0xfffffff1,0xf);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_8c = FLOAT_803dfb60 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0) +
                 FLOAT_803dfa88;
      uStack36 = FUN_800221a0(0xfffffff1,0xf);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_88 = FLOAT_803dfb60 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0) +
                 FLOAT_803dfa88;
      uStack44 = FUN_800221a0(0xfffffff1,0xf);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfb60 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0) +
                 FLOAT_803dfa88;
      local_7c = FLOAT_803dfb64;
      FUN_80021ac8(param_3,&local_8c);
      uStack52 = FUN_800221a0(0x14,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb68 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_50 = -1;
      local_a8 = 100;
      local_4f = 0x10;
      local_ac = 0x1b4;
      local_6c = (undefined *)0x480200;
      local_68 = 0x100000;
      local_6e = 0x159;
      break;
    case 0x1b4:
      uStack28 = FUN_800221a0(0x14,0x1e);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb6c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_50 = '7';
      local_a8 = 0x14;
      local_4f = 0x10;
      local_6c = (undefined *)0x80201;
      local_68 = 2;
      local_6e = 0x159;
      break;
    case 0x1b6:
      if (param_3 == (undefined2 *)0x0) {
        uStack28 = FUN_800221a0(0xfffffffd,3);
        uStack28 = uStack28 ^ 0x80000000;
        local_20 = 0x43300000;
        local_88 = FLOAT_803dfad8 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0)
        ;
      }
      else {
        local_88 = *(float *)(param_3 + 4);
      }
      local_74 = FLOAT_803dfb00;
      local_a8 = 0x32;
      local_50 = -1;
      local_4f = 0x10;
      local_6c = (undefined *)0x88100200;
      local_6e = 0xc79;
      break;
    case 0x1b8:
      uStack28 = FUN_800221a0(0xfffff448,3000);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xfffff448,3000);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(1,4);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfbc8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = 0x5a;
      local_50 = -1;
      local_6c = (undefined *)0xa100100;
      local_6e = 0x56;
      break;
    case 0x1b9:
      uStack28 = FUN_800221a0(0xfffffd44,700);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,1000);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_80 = FLOAT_803dfb9c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0) +
                 FLOAT_803dfb98;
      local_7c = FLOAT_803dfba0 * local_80;
      uStack44 = FUN_800221a0(0,10);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfba8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0) +
                 FLOAT_803dfba4;
      local_88 = FLOAT_803dfba0 * local_8c;
      uStack52 = FUN_800221a0(1,6);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfbac * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = 0xbe;
      local_50 = -1;
      local_6c = (undefined *)0x6000100;
      local_6e = 0x20;
      local_a0 = 0;
      local_a2 = 0x5fb4;
      local_a4 = 0xc001;
      local_98 = FLOAT_803dfa9c;
      local_94 = FLOAT_803dfa9c;
      local_90 = FLOAT_803dfa9c;
      break;
    case 0x1ba:
      local_7c = FLOAT_803dfbc0;
      uStack28 = FUN_800221a0(0xfffffc18,1000);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffff38,200);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      local_7c = FLOAT_803dfba0 * local_80;
      uStack44 = FUN_800221a0(1,6);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfbc4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = 0x82;
      local_50 = -1;
      local_6c = (undefined *)0x1000000;
      local_68 = 0x200000;
      local_6e = 0x20;
      break;
    case 0x1bc:
      uStack28 = FUN_800221a0(0xffffff9c,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffff9c,100);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dfabc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0x4b,100);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb18 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = FUN_800221a0(0x8c,0xa5);
      local_50 = '7';
      local_6e = 0x167;
      local_6c = (undefined *)0x80000;
      local_68 = 0x4400000;
      break;
    case 0x1bd:
      uStack28 = FUN_800221a0(0x4b,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_74 = FLOAT_803dfb1c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_50 = '7';
      local_a8 = 0xf;
      local_4f = 0x10;
      local_6e = 100;
      local_6c = (undefined *)0x4080100;
      break;
    case 0x1bf:
      uStack28 = FUN_800221a0(0xffffff9c,100);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0,1000);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(0xffffff9c,100);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xffffffd8,0x28);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_8c = FLOAT_803dfb38 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(500,600);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_88 = FLOAT_803dfbb0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      uStack68 = FUN_800221a0(0xffffffd8,0x28);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_84 = FLOAT_803dfb38 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfbb4;
      local_a8 = 0x15e;
      local_50 = -1;
      local_68 = 0x300020;
      local_6c = (undefined *)0x3008000;
      local_58 = 0xffff;
      local_56 = 0xffff;
      local_54 = 0xffff;
      local_64 = 0x63bf;
      local_60 = 0x9e7;
      local_5c = 1000;
      local_6e = 0x23b;
      break;
    case 0x1c0:
      uStack28 = FUN_800221a0(0xfffffd44,700);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xfffffd44,700);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(500,600);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dfbb0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfbb4;
      local_a8 = 0x96;
      local_50 = -1;
      local_68 = 0x200000;
      local_6c = (undefined *)0x2000200;
      local_6e = 0x23b;
      break;
    case 0x1c1:
      uStack28 = FUN_800221a0(0xfffffd44,700);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xfffffd44,700);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(500,600);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_88 = FLOAT_803dfbb8 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0x1e,0x32);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_74 = FLOAT_803dfb48 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      local_a8 = 0x96;
      local_50 = -0x65;
      local_68 = 0x20;
      local_6c = (undefined *)0x80100;
      sVar3 = FUN_800221a0(0,30000);
      local_58 = sVar3 + 0x63bf;
      iVar2 = FUN_800221a0(1,3);
      local_56 = (undefined2)((int)(uint)local_58 / iVar2);
      local_54 = 0;
      local_64 = FUN_800221a0(0,10000);
      local_60 = FUN_800221a0(1,3);
      local_60 = local_64 / local_60;
      local_5c = 0;
      local_6e = 0x60;
      break;
    case 0x1c2:
      uStack28 = FUN_800221a0(0xffffff38,200);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xffffff38,200);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(200,800);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_84 = FLOAT_803dfbb0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      iVar2 = FUN_800221a0(0,1);
      if (iVar2 != 0) {
        local_84 = local_84 * FLOAT_803dfbbc;
      }
      uStack28 = FUN_800221a0(200,800);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_88 = FLOAT_803dfbb0 * (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      iVar2 = FUN_800221a0(0,1);
      if (iVar2 != 0) {
        local_88 = local_88 * FLOAT_803dfbbc;
      }
      local_74 = FLOAT_803dfac4;
      local_a8 = FUN_800221a0(0,0x1e);
      local_a8 = local_a8 + 0x14;
      local_50 = -1;
      local_68 = 0x200000;
      local_6c = (undefined *)0x2000200;
      local_6e = 0x23b;
      break;
    case 0x1c3:
      local_88 = FLOAT_803dfa8c;
      local_74 = FLOAT_803dfac4;
      local_a8 = 0x3c;
      local_50 = -1;
      local_6c = (undefined *)0xa100110;
      local_6e = 0x23b;
      break;
    case 0x1c4:
      local_80 = FLOAT_803dfac0;
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = FUN_800221a0(0);
      local_c6 = FUN_800221a0(0,0xffff);
      local_c8 = FUN_800221a0(0,0xffff);
      FUN_80021ac8(&local_c8,&local_80);
      local_74 = FLOAT_803dfac4;
      local_a8 = 200;
      local_50 = -1;
      local_6c = (undefined *)0x480100;
      local_6e = 0x26c;
      break;
    case 0x1c5:
      local_80 = FLOAT_803dfab8;
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = FUN_800221a0(0);
      local_c6 = FUN_800221a0(0,0xffff);
      local_c8 = FUN_800221a0(0,0xffff);
      FUN_80021ac8(&local_c8,&local_80);
      local_74 = FLOAT_803dfabc;
      local_a8 = 200;
      local_50 = -1;
      local_6c = (undefined *)0x480100;
      local_6e = 0x33;
      break;
    case 0x1c6:
      uStack28 = FUN_800221a0(0,0x5a);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_80 = FLOAT_803dfac8 + (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0xfffffff6,10);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = 0;
      local_c6 = 0;
      local_c8 = FUN_800221a0(0,0xffff);
      FUN_80021ac8(&local_c8,&local_80);
      uStack44 = FUN_800221a0(1,0x14);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfacc * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = 200;
      local_50 = -1;
      local_6c = (undefined *)0x480100;
      local_68 = 0x2000000;
      local_6e = 0x23c;
      break;
    case 0x1c7:
      uStack44 = FUN_800221a0(0xffffffe4,0x1c);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xffffffe4,0x1c);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_88 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(0xffffffe4,0x1c);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      uStack68 = FUN_800221a0(0xffffffba,0x46);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_80 = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfbd0);
      uStack36 = FUN_800221a0(0x82,0xaa);
      uStack36 = uStack36 ^ 0x80000000;
      local_28 = 0x43300000;
      local_7c = (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803dfbd0);
      uStack28 = FUN_800221a0(0xffffffba,0x46);
      uStack28 = uStack28 ^ 0x80000000;
      local_20 = 0x43300000;
      local_78 = (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803dfbd0);
      local_74 = FLOAT_803dfab0;
      local_a8 = 400;
      local_50 = -1;
      local_58 = 0;
      local_56 = 0;
      local_54 = 0;
      local_64 = 0;
      local_60 = 0;
      local_5c = 0;
      local_6c = (undefined *)0x80480108;
      local_68 = 0x20;
      local_6e = 0x33;
      break;
    case 0x1c8:
      uStack68 = FUN_800221a0(0,100);
      uStack68 = uStack68 ^ 0x80000000;
      local_48 = 0x43300000;
      local_7c = FLOAT_803dfa8c * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(0xffffffd8,0x28);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_8c = FLOAT_803dfaa0 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xffffffe2,0x1e);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = local_8c *
                 FLOAT_803dfaa0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack44 = FUN_800221a0(200,0x118);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfaa4 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = 0x32;
      local_50 = -1;
      local_6c = (undefined *)0x80118;
      local_68 = 8;
      local_6e = 0x566;
      break;
    case 0x1c9:
      local_78 = FLOAT_803dfaa8;
      local_bc = FLOAT_803dfa9c;
      local_b8 = FLOAT_803dfa9c;
      local_b4 = FLOAT_803dfa9c;
      local_c0 = FLOAT_803dfa90;
      local_c4 = 0;
      local_c6 = 0;
      local_c8 = FUN_800221a0(0);
      FUN_80021ac8(&local_c8,&local_80);
      uStack44 = FUN_800221a0(200,0x118);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_74 = FLOAT_803dfaac * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      local_a8 = 0x14;
      local_50 = -0x1f;
      local_6c = (undefined *)0x400000;
      local_6e = 0x4f9;
      break;
    case 0x1ca:
      uStack44 = FUN_800221a0(0xffffffe4,0x1c);
      uStack44 = uStack44 ^ 0x80000000;
      local_30 = 0x43300000;
      local_8c = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803dfbd0);
      uStack52 = FUN_800221a0(0xffffffe4,0x1c);
      uStack52 = uStack52 ^ 0x80000000;
      local_38 = 0x43300000;
      local_84 = FLOAT_803dfab0 * (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803dfbd0);
      uStack60 = FUN_800221a0(200,0x118);
      uStack60 = uStack60 ^ 0x80000000;
      local_40 = 0x43300000;
      local_74 = FLOAT_803dfab4 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803dfbd0);
      local_a8 = 200;
      local_50 = -0x1f;
      local_6c = (undefined *)0x400110;
      iVar2 = FUN_800221a0(0,2);
      if (iVar2 == 0) {
        local_68 = local_68 | 0x100;
      }
      else {
        local_68 = local_68 | 0x400;
      }
      local_6e = 0x4f9;
    }
    local_6c = (undefined *)((uint)local_6c | param_4);
    if ((((uint)local_6c & 1) != 0) && (((uint)local_6c & 2) != 0)) {
      local_6c = (undefined *)((uint)local_6c ^ 2);
    }
    if (((uint)local_6c & 1) != 0) {
      if ((param_4 & 0x200000) == 0) {
        if (local_b0 != 0) {
          local_80 = local_80 + *(float *)(local_b0 + 0x18);
          local_7c = local_7c + *(float *)(local_b0 + 0x1c);
          local_78 = local_78 + *(float *)(local_b0 + 0x20);
        }
      }
      else {
        local_80 = local_80 + local_98;
        local_7c = local_7c + local_94;
        local_78 = local_78 + local_90;
      }
    }
    uVar1 = (**(code **)(*DAT_803dca78 + 8))(&local_b0,0xffffffff,(int)uVar4,0);
  }
LAB_800bc0f8:
  FUN_80286124(uVar1);
  return;
}

