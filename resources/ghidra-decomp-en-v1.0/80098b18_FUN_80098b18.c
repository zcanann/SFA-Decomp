// Function: FUN_80098b18
// Entry: 80098b18
// Size: 2888 bytes

/* WARNING: Removing unreachable block (ram,0x80099640) */

void FUN_80098b18(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,float *param_5)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  undefined4 unaff_r30;
  undefined4 uVar5;
  double extraout_f1;
  undefined8 in_f31;
  double dVar6;
  undefined8 uVar7;
  undefined auStack72 [4];
  undefined2 local_44;
  undefined2 local_42;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar7 = FUN_802860d0();
  uVar3 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar2 = (uint)DAT_803db410;
  if (3 < uVar2) {
    uVar2 = 3;
  }
  local_40 = (float)extraout_f1;
  if (param_5 == (float *)0x0) {
    local_3c = FLOAT_803df35c;
    local_38 = FLOAT_803df35c;
    local_34 = FLOAT_803df35c;
  }
  else {
    local_3c = *param_5;
    local_38 = param_5[1];
    local_34 = param_5[2];
  }
  uVar1 = (uint)uVar7 & 0xff;
  if (uVar1 != 0xb) {
    if (uVar1 < 0xb) {
      if (uVar1 == 3) {
        local_40 = local_40 * FLOAT_803df388;
        unaff_r30 = 0x7b0;
        goto LAB_80098c08;
      }
      if ((2 < uVar1) && (8 < uVar1)) {
        param_4 = 0;
        param_3 = 0;
        goto LAB_80098c08;
      }
    }
    else if (uVar1 < 0xf) {
      param_4 = 0;
      if ((param_3 & 0xff) != 0) {
        param_3 = 8;
      }
      goto LAB_80098c08;
    }
  }
  unaff_r30 = 0x7af;
LAB_80098c08:
  dVar6 = extraout_f1;
  switch(param_3 & 0xff) {
  case 1:
    local_42 = 45000;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    break;
  case 2:
    local_42 = 10000;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    break;
  case 3:
    local_42 = 500;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    break;
  case 4:
    local_42 = 0xffff;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    break;
  case 5:
    local_42 = 0x7fff;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    break;
  case 6:
    local_42 = 10000;
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ad,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    break;
  case 7:
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ae,auStack72,1,0xffffffff,0);
    break;
  case 8:
    if (local_40 < FLOAT_803df358) {
      local_40 = FLOAT_803df358;
    }
    local_44 = 0x5a;
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bd,auStack72,1,0xffffffff,0);
    }
  }
  param_4 = param_4 & 0xff;
  if (param_4 != 0) {
    if (param_4 == 2) {
      local_42 = 0xc0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,unaff_r30,auStack72,1,0xffffffff,0);
    }
    else if (param_4 < 2) {
      if (param_4 != 0) {
        local_42 = 0x7f;
        (**(code **)(*DAT_803dca88 + 8))(uVar3,unaff_r30,auStack72,1,0xffffffff,0);
      }
    }
    else if (param_4 < 4) {
      local_42 = 0xff;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,unaff_r30,auStack72,1,0xffffffff,0);
    }
  }
  local_40 = (float)dVar6;
  switch(uVar1) {
  case 1:
    local_42 = 0xc0d;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7a8,auStack72,1,0xffffffff,0);
    }
    break;
  case 2:
    local_42 = 0xc0a;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7a9,auStack72,1,0xffffffff,0);
    }
    break;
  case 3:
    local_42 = 0xc0a;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7aa,auStack72,1,0xffffffff,0);
    }
    break;
  case 4:
    local_42 = 0xc0e;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ab,auStack72,1,0xffffffff,0);
    }
    break;
  case 5:
    local_42 = 0x84;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ab,auStack72,1,0xffffffff,0);
    }
    break;
  case 6:
    local_42 = 0xc0f;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ab,auStack72,1,0xffffffff,0);
    }
    break;
  case 7:
    local_42 = 100;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ac,auStack72,1,0xffffffff,0);
    }
    break;
  case 8:
    local_42 = 0xc7e;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ac,auStack72,1,0xffffffff,0);
    }
    break;
  case 9:
    if ((float)dVar6 < FLOAT_803df358) {
      local_40 = FLOAT_803df358;
    }
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7b5,auStack72,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7b5,auStack72,1,0xffffffff,0);
    }
    break;
  case 10:
    if ((float)dVar6 < FLOAT_803df358) {
      local_40 = FLOAT_803df358;
    }
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7b6,auStack72,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7b6,auStack72,1,0xffffffff,0);
    }
    break;
  case 0xb:
    local_42 = 100;
    for (iVar4 = 0; iVar4 < (int)uVar2; iVar4 = iVar4 + 1) {
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7ac,auStack72,1,0xffffffff,0);
    }
    break;
  case 0xc:
    if ((float)dVar6 < FLOAT_803df38c) {
      local_40 = FLOAT_803df38c;
    }
    local_44 = 0x32;
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bb,auStack72,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bb,auStack72,1,0xffffffff,0);
    }
    break;
  case 0xd:
    if ((float)dVar6 < FLOAT_803df358) {
      local_40 = FLOAT_803df358;
    }
    local_44 = 0x5a;
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bc,auStack72,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bc,auStack72,1,0xffffffff,0);
    }
    break;
  case 0xe:
    if ((float)dVar6 < FLOAT_803df358) {
      local_40 = FLOAT_803df358;
    }
    local_44 = 0xf0;
    for (iVar4 = 0; iVar4 < (int)(uVar2 << 1); iVar4 = iVar4 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bc,auStack72,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dca88 + 8))(uVar3,0x7bc,auStack72,1,0xffffffff,0);
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_8028611c();
  return;
}

