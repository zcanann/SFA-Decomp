// Function: FUN_8022cdec
// Entry: 8022cdec
// Size: 1308 bytes

void FUN_8022cdec(int param_1,int param_2)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  float local_18 [2];
  
  local_18[0] = FLOAT_803e6fc0;
  iVar5 = (**(code **)(*DAT_803dcaac + 0x8c))();
  if (*(int *)(param_2 + 4) == 0) {
    uVar6 = FUN_800380e0(param_1,0x606,local_18);
    *(undefined4 *)(param_2 + 4) = uVar6;
    if (*(int *)(param_2 + 4) != 0) {
      FUN_80037d2c(param_1,*(int *)(param_2 + 4),0);
    }
  }
  if (*(char *)(param_2 + 0x480) != '\0') {
    if (*(int *)(param_2 + 0x10) == 0) {
      uVar6 = FUN_800380e0(param_1,0x611,local_18);
      *(undefined4 *)(param_2 + 0x10) = uVar6;
      if (*(int *)(param_2 + 0x10) != 0) {
        FUN_80037d2c(param_1,*(int *)(param_2 + 0x10),0);
      }
    }
    if (*(int *)(param_2 + 8) == 0) {
      uVar6 = FUN_800380e0(param_1,0x610,local_18);
      *(undefined4 *)(param_2 + 8) = uVar6;
      if (*(int *)(param_2 + 8) != 0) {
        FUN_80037d2c(param_1,*(int *)(param_2 + 8),0);
      }
    }
    if (*(int *)(param_2 + 0xc) == 0) {
      uVar6 = FUN_800380e0(param_1,0x615,local_18);
      *(undefined4 *)(param_2 + 0xc) = uVar6;
      if (*(int *)(param_2 + 0xc) != 0) {
        FUN_80037d2c(param_1,*(int *)(param_2 + 0xc),0);
      }
    }
  }
  if ((*(int *)(param_2 + 0x418) == 0) && (*(int *)(param_2 + 0x41c) == 0)) {
    iVar7 = FUN_8002bdf4(0x20,0x6de);
    *(undefined *)(iVar7 + 4) = 1;
    *(undefined *)(iVar7 + 5) = 1;
    uVar6 = FUN_8002b5a0(param_1);
    *(undefined4 *)(param_2 + 0x418) = uVar6;
    iVar7 = FUN_8002bdf4(0x20,0x6de);
    *(undefined *)(iVar7 + 4) = 1;
    *(undefined *)(iVar7 + 5) = 1;
    uVar6 = FUN_8002b5a0(param_1);
    *(undefined4 *)(param_2 + 0x41c) = uVar6;
  }
  bVar1 = false;
  if (*(char *)(param_2 + 0x480) == '\0') {
    if (*(int *)(param_2 + 4) != 0) {
      bVar1 = true;
    }
  }
  else {
    if (*(int *)(param_2 + 0x450) == 0) {
      uVar6 = FUN_8001f4c8(param_1,1);
      *(undefined4 *)(param_2 + 0x450) = uVar6;
      if (*(int *)(param_2 + 0x450) != 0) {
        FUN_8001db2c(*(int *)(param_2 + 0x450),2);
        FUN_8001dd88((double)FLOAT_803e6ecc,(double)FLOAT_803e6fc4,(double)FLOAT_803e6fc8,
                     *(undefined4 *)(param_2 + 0x450));
        FUN_8001db14(*(undefined4 *)(param_2 + 0x450),1);
        FUN_8001daf0(*(undefined4 *)(param_2 + 0x450),0x28,0x7d,0xff,0);
        FUN_8001dc38((double)FLOAT_803e6fcc,(double)FLOAT_803e6fd0,*(undefined4 *)(param_2 + 0x450))
        ;
        FUN_8001d620(*(undefined4 *)(param_2 + 0x450),1,1);
        FUN_8001dab8(*(undefined4 *)(param_2 + 0x450),0x14,100,200,0);
      }
    }
    if ((((*(int *)(param_2 + 4) != 0) && (*(int *)(param_2 + 0x10) != 0)) &&
        (*(int *)(param_2 + 8) != 0)) && (*(int *)(param_2 + 0xc) != 0)) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    (**(code **)(*DAT_803dca50 + 0x28))(param_1,0);
    *(byte *)(param_2 + 0x477) = *(byte *)(param_2 + 0x477) | 1;
    *(float *)(param_2 + 0x54) = FLOAT_803e6f70;
    fVar2 = FLOAT_803e6f74;
    *(float *)(param_2 + 0x60) = FLOAT_803e6f74;
    fVar3 = FLOAT_803e6f78;
    *(float *)(param_2 + 0x58) = FLOAT_803e6f78;
    fVar4 = FLOAT_803e6f7c;
    *(float *)(param_2 + 100) = FLOAT_803e6f7c;
    *(float *)(param_2 + 0x5c) = fVar3;
    *(float *)(param_2 + 0x68) = fVar4;
    *(float *)(param_2 + 0x78) = FLOAT_803e6f80;
    *(float *)(param_2 + 0x84) = FLOAT_803e6f84;
    *(float *)(param_2 + 0x6c) = FLOAT_803e6ed0;
    *(float *)(param_2 + 0x348) = FLOAT_803e6f88;
    *(float *)(param_2 + 0x34c) = fVar2;
    *(float *)(param_2 + 0x35c) = FLOAT_803e6f8c;
    *(float *)(param_2 + 0x360) = fVar4;
    *(float *)(param_2 + 0x370) = FLOAT_803e6f90;
    *(float *)(param_2 + 0x374) = FLOAT_803e6f94;
    *(float *)(param_2 + 900) = FLOAT_803e6f98;
    *(float *)(param_2 + 0x388) = FLOAT_803e6f9c;
    *(float *)(param_2 + 0x394) = FLOAT_803e6fa0;
    *(float *)(param_2 + 0x390) = FLOAT_803e6fa4;
    *(float *)(param_2 + 0x39c) = FLOAT_803e6fa8;
    *(undefined *)(param_2 + 0x3fa) = 0x19;
    *(float *)(param_2 + 0x3a4) = FLOAT_803e6fac;
    fVar4 = FLOAT_803e6fb0;
    *(float *)(param_2 + 0x38) = FLOAT_803e6fb0;
    *(float *)(param_1 + 8) = fVar4;
    *(float *)(param_2 + 0x3ac) = FLOAT_803e6fb4;
    *(float *)(param_2 + 0x3b0) = FLOAT_803e6fb8;
    *(float *)(param_2 + 0x88) = FLOAT_803e6fbc;
    *(float *)(param_2 + 0x8c) = FLOAT_803e6f64;
    *(float *)(param_2 + 0x90) = FLOAT_803e6fd4;
    *(float *)(param_2 + 0x94) = fVar2;
    *(float *)(param_2 + 0x98) = FLOAT_803e6fd8;
    *(float *)(param_2 + 0xb8) = FLOAT_803e6fdc;
    *(float *)(param_2 + 0xa0) = FLOAT_803e6fe0;
    *(float *)(param_2 + 0xa8) = FLOAT_803e6f2c;
    *(undefined4 *)(param_2 + 0x9c) = *(undefined4 *)(param_2 + 0xa0);
    *(undefined4 *)(param_2 + 0xa4) = *(undefined4 *)(param_2 + 0xa8);
    fVar2 = FLOAT_803e6f5c;
    *(float *)(param_2 + 0xac) = FLOAT_803e6f5c;
    *(float *)(param_2 + 0xb0) = fVar2;
    if (*(char *)(param_1 + 0xac) == '&') {
      *(float *)(param_2 + 0x50) = FLOAT_803e6ecc;
    }
    else {
      *(float *)(param_2 + 0x50) = fVar3;
    }
    *(undefined2 *)(param_2 + 0x40e) = 0x28;
    *(float *)(param_2 + 0x410) = FLOAT_803e6fe0;
    *(undefined2 *)(param_2 + 0x40c) = 6;
    *(undefined2 *)(param_2 + 0x446) = 0x5a;
    *(float *)(param_2 + 0x448) = FLOAT_803e6f34;
    *(undefined2 *)(param_2 + 0x444) = 0xc;
    *(undefined *)(param_2 + 0x44d) = 3;
    uVar6 = FUN_800395d8(param_1,0);
    *(undefined4 *)(param_2 + 0x454) = uVar6;
    uVar6 = FUN_800395d8(param_1,1);
    *(undefined4 *)(param_2 + 0x458) = uVar6;
    uVar6 = FUN_800395d8(param_1,2);
    *(undefined4 *)(param_2 + 0x45c) = uVar6;
    uVar6 = FUN_800395d8(param_1,3);
    *(undefined4 *)(param_2 + 0x460) = uVar6;
    *(float *)(param_2 + 0x464) = FLOAT_803e6f64;
    *(undefined2 *)(param_2 + 0x44e) = 0xaf;
    *(undefined *)(param_2 + 0x469) = *(undefined *)(iVar5 + 1);
    *(undefined *)(param_2 + 0x468) = *(undefined *)(param_2 + 0x469);
    *(float *)(param_2 + 0x3b4) = FLOAT_803e6ef8;
    fVar2 = FLOAT_803e6ef0;
    *(float *)(param_2 + 0x3b8) = FLOAT_803e6ef0;
    *(float *)(param_2 + 0x3bc) = FLOAT_803e6fe4;
    *(float *)(param_2 + 0x3c4) = FLOAT_803e6ef4;
    *(float *)(param_2 + 0x3c8) = FLOAT_803e6fd4;
    *(float *)(param_2 + 0x3d0) = FLOAT_803e6fe8;
    *(float *)(param_2 + 0x3d4) = FLOAT_803e6f80;
    *(float *)(param_2 + 0x3e0) = FLOAT_803e6fa4;
    *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_2 + 0x1c) = *(undefined4 *)(param_1 + 0x14);
    *(float *)(param_2 + 0x20) = FLOAT_803e6fec;
    *(float *)(param_2 + 0x28) = FLOAT_803e6ff0;
    *(float *)(param_2 + 0x24) = fVar2;
  }
  return;
}

