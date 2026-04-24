// Function: FUN_80098da4
// Entry: 80098da4
// Size: 2888 bytes

/* WARNING: Removing unreachable block (ram,0x800998cc) */
/* WARNING: Removing unreachable block (ram,0x80098db4) */

void FUN_80098da4(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,
                 undefined4 *param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 unaff_r30;
  double extraout_f1;
  double in_f31;
  double dVar6;
  double in_ps31_1;
  undefined8 uVar7;
  undefined auStack_48 [4];
  undefined2 local_44;
  undefined2 local_42;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar7 = FUN_80286834();
  uVar4 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar3 = (uint)DAT_803dc070;
  if (3 < uVar3) {
    uVar3 = 3;
  }
  local_40 = (float)extraout_f1;
  if ((float *)param_5 == (float *)0x0) {
    local_3c = FLOAT_803dffdc;
    local_38 = FLOAT_803dffdc;
    local_34 = FLOAT_803dffdc;
  }
  else {
    local_3c = (float)*param_5;
    local_38 = ((float *)param_5)[1];
    local_34 = ((float *)param_5)[2];
  }
  uVar1 = (uint)uVar7 & 0xff;
  if (uVar1 != 0xb) {
    if (uVar1 < 0xb) {
      if (uVar1 == 3) {
        local_40 = local_40 * FLOAT_803e0008;
        unaff_r30 = 0x7b0;
        goto LAB_80098e94;
      }
      if ((2 < uVar1) && (8 < uVar1)) {
        param_4 = 0;
        param_3 = 0;
        goto LAB_80098e94;
      }
    }
    else if (uVar1 < 0xf) {
      param_4 = 0;
      if ((param_3 & 0xff) != 0) {
        param_3 = 8;
      }
      goto LAB_80098e94;
    }
  }
  unaff_r30 = 0x7af;
LAB_80098e94:
  dVar6 = extraout_f1;
  switch(param_3 & 0xff) {
  case 1:
    local_42 = 45000;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    break;
  case 2:
    local_42 = 10000;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    break;
  case 3:
    local_42 = 500;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    break;
  case 4:
    local_42 = 0xffff;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    break;
  case 5:
    local_42 = 0x7fff;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    break;
  case 6:
    local_42 = 10000;
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ad,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    break;
  case 7:
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ae,auStack_48,1,0xffffffff,0);
    break;
  case 8:
    if (local_40 < FLOAT_803dffd8) {
      local_40 = FLOAT_803dffd8;
    }
    local_44 = 0x5a;
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bd,auStack_48,1,0xffffffff,0);
    }
  }
  uVar2 = param_4 & 0xff;
  if (uVar2 != 0) {
    if (uVar2 == 2) {
      local_42 = 0xc0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,unaff_r30,auStack_48,1,0xffffffff,0);
    }
    else if (uVar2 < 2) {
      if (uVar2 != 0) {
        local_42 = 0x7f;
        (**(code **)(*DAT_803dd708 + 8))(uVar4,unaff_r30,auStack_48,1,0xffffffff,0);
      }
    }
    else if (uVar2 < 4) {
      local_42 = 0xff;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,unaff_r30,auStack_48,1,0xffffffff,0);
    }
  }
  local_40 = (float)dVar6;
  switch(uVar1) {
  case 1:
    local_42 = 0xc0d;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7a8,auStack_48,1,0xffffffff,0);
    }
    break;
  case 2:
    local_42 = 0xc0a;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7a9,auStack_48,1,0xffffffff,0);
    }
    break;
  case 3:
    local_42 = 0xc0a;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7aa,auStack_48,1,0xffffffff,0);
    }
    break;
  case 4:
    local_42 = 0xc0e;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ab,auStack_48,1,0xffffffff,0);
    }
    break;
  case 5:
    local_42 = 0x84;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ab,auStack_48,1,0xffffffff,0);
    }
    break;
  case 6:
    local_42 = 0xc0f;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ab,auStack_48,1,0xffffffff,0);
    }
    break;
  case 7:
    local_42 = 100;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ac,auStack_48,1,0xffffffff,0);
    }
    break;
  case 8:
    local_42 = 0xc7e;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ac,auStack_48,1,0xffffffff,0);
    }
    break;
  case 9:
    if ((float)dVar6 < FLOAT_803dffd8) {
      local_40 = FLOAT_803dffd8;
    }
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7b5,auStack_48,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7b5,auStack_48,1,0xffffffff,0);
    }
    break;
  case 10:
    if ((float)dVar6 < FLOAT_803dffd8) {
      local_40 = FLOAT_803dffd8;
    }
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7b6,auStack_48,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7b6,auStack_48,1,0xffffffff,0);
    }
    break;
  case 0xb:
    local_42 = 100;
    for (iVar5 = 0; iVar5 < (int)uVar3; iVar5 = iVar5 + 1) {
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7ac,auStack_48,1,0xffffffff,0);
    }
    break;
  case 0xc:
    if ((float)dVar6 < FLOAT_803e000c) {
      local_40 = FLOAT_803e000c;
    }
    local_44 = 0x32;
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bb,auStack_48,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bb,auStack_48,1,0xffffffff,0);
    }
    break;
  case 0xd:
    if ((float)dVar6 < FLOAT_803dffd8) {
      local_40 = FLOAT_803dffd8;
    }
    local_44 = 0x5a;
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bc,auStack_48,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bc,auStack_48,1,0xffffffff,0);
    }
    break;
  case 0xe:
    if ((float)dVar6 < FLOAT_803dffd8) {
      local_40 = FLOAT_803dffd8;
    }
    local_44 = 0xf0;
    for (iVar5 = 0; iVar5 < (int)(uVar3 << 1); iVar5 = iVar5 + 1) {
      local_42 = 0;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bc,auStack_48,1,0xffffffff,0);
      local_42 = 1;
      (**(code **)(*DAT_803dd708 + 8))(uVar4,0x7bc,auStack_48,1,0xffffffff,0);
    }
  }
  FUN_80286880();
  return;
}

