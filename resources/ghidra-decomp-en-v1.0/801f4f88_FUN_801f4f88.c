// Function: FUN_801f4f88
// Entry: 801f4f88
// Size: 1088 bytes

void FUN_801f4f88(undefined2 *param_1)

{
  char cVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 uVar6;
  int iVar7;
  double dVar8;
  double local_20;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  iVar4 = FUN_8002b9ec();
  if (*(byte *)(param_1 + 0x1b) < 0xff) {
    iVar3 = (int)(FLOAT_803e5edc * FLOAT_803db414 +
                 (float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1b) ^ 0x80000000) -
                        DOUBLE_803e5ed0));
    if (0xff < iVar3) {
      iVar3 = 0xff;
    }
    *(char *)(param_1 + 0x1b) = (char)iVar3;
  }
  if (FLOAT_803e5eb4 < *(float *)(iVar7 + 0x40)) {
    *(float *)(iVar7 + 0x40) = *(float *)(iVar7 + 0x40) - FLOAT_803e5eb4;
    if (*(byte *)(iVar7 + 0x68) < 4) {
      FUN_801f4d54(param_1,iVar7);
    }
    else {
      *(byte *)(iVar7 + 0x68) = *(byte *)(iVar7 + 0x68) + 1;
    }
    *(undefined4 *)(iVar7 + 4) = *(undefined4 *)(iVar7 + 8);
    *(undefined4 *)(iVar7 + 0x14) = *(undefined4 *)(iVar7 + 0x18);
    *(undefined4 *)(iVar7 + 0x24) = *(undefined4 *)(iVar7 + 0x28);
    *(undefined4 *)(iVar7 + 8) = *(undefined4 *)(iVar7 + 0xc);
    *(undefined4 *)(iVar7 + 0x18) = *(undefined4 *)(iVar7 + 0x1c);
    *(undefined4 *)(iVar7 + 0x28) = *(undefined4 *)(iVar7 + 0x2c);
    *(undefined4 *)(iVar7 + 0xc) = *(undefined4 *)(iVar7 + 0x10);
    *(undefined4 *)(iVar7 + 0x1c) = *(undefined4 *)(iVar7 + 0x20);
    *(undefined4 *)(iVar7 + 0x2c) = *(undefined4 *)(iVar7 + 0x30);
    uVar5 = FUN_800221a0(0xa0,0xb4);
    local_20 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
    *(float *)(iVar7 + 0x44) = FLOAT_803e5ed8 * (float)(local_20 - DOUBLE_803e5ed0);
    *(undefined4 *)(iVar7 + 0x10) = *(undefined4 *)(iVar7 + 0x34);
    *(undefined4 *)(iVar7 + 0x20) = *(undefined4 *)(iVar7 + 0x38);
    *(undefined4 *)(iVar7 + 0x30) = *(undefined4 *)(iVar7 + 0x3c);
  }
  dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar7 + 0x40),iVar7 + 4,0);
  *(float *)(param_1 + 6) = (float)dVar8;
  dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar7 + 0x40),iVar7 + 0x14,0);
  *(float *)(param_1 + 8) = (float)dVar8;
  dVar8 = (double)FUN_80010ee0((double)*(float *)(iVar7 + 0x40),iVar7 + 0x24,0);
  *(float *)(param_1 + 10) = (float)dVar8;
  *(float *)(iVar7 + 0x40) = *(float *)(iVar7 + 0x44) * FLOAT_803db414 + *(float *)(iVar7 + 0x40);
  uVar6 = FUN_800217c0((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)),
                       (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44)));
  *param_1 = uVar6;
  if ((*(char *)(iVar7 + 0x66) == '\x01') || (*(char *)(iVar7 + 0x66) == '\x04')) {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x1a0,0,1,0xffffffff,0);
  }
  else {
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x1bd,0,1,0xffffffff,0);
  }
  dVar8 = (double)FUN_80021690(iVar4 + 0x18,*(int *)(param_1 + 0x26) + 8);
  fVar2 = FLOAT_803e5ee8;
  if ((double)*(float *)(iVar7 + 0x4c) <= dVar8) {
    if ((FLOAT_803e5ee8 < *(float *)(iVar7 + 0x48)) &&
       (*(float *)(iVar7 + 0x48) = *(float *)(iVar7 + 0x48) - FLOAT_803e5ee4,
       *(float *)(iVar7 + 0x48) < fVar2)) {
      *(float *)(iVar7 + 0x48) = fVar2;
    }
  }
  else {
    cVar1 = *(char *)(iVar7 + 0x66);
    if (cVar1 == '\x04') {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x19f,0,1,0xffffffff,0);
    }
    else if (cVar1 == '\x03') {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x1bc,0,1,0xffffffff,0);
    }
    else if (cVar1 == '\x05') {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x1bc,0,1,0xffffffff,0);
    }
    fVar2 = FLOAT_803e5ee0;
    if ((*(float *)(iVar7 + 0x48) < FLOAT_803e5ee0) &&
       (*(float *)(iVar7 + 0x48) = *(float *)(iVar7 + 0x48) + FLOAT_803e5ee4,
       fVar2 < *(float *)(iVar7 + 0x48))) {
      *(float *)(iVar7 + 0x48) = fVar2;
    }
  }
  fVar2 = *(float *)(param_1 + 8) - *(float *)(iVar4 + 0x10);
  if (((((*(byte *)(iVar7 + 0x7c) & 1) == 0) && (fVar2 < FLOAT_803e5eec)) &&
      (FLOAT_803e5ec4 < fVar2)) &&
     (dVar8 = (double)FUN_8002166c(param_1 + 0xc,iVar4 + 0x18), dVar8 < (double)FLOAT_803e5ef0)) {
    *(byte *)(iVar7 + 0x7c) = *(byte *)(iVar7 + 0x7c) | 1;
    iVar3 = FUN_8001ffb4(0xd28);
    if (iVar3 == 0) {
      *(undefined2 *)(iVar7 + 0x80) = 0xffff;
      FUN_800378c4(iVar4,0x7000a,param_1,iVar7 + 0x80);
      FUN_800200e8(0xd28,1);
    }
    else {
      param_1[3] = param_1[3] | 0x4000;
      *(float *)(*(int *)(param_1 + 0x5c) + 0x70) = FLOAT_803e5ea8;
      FUN_8001ff3c(0x13d);
      FUN_8001ff3c(0x5d6);
      FUN_8000bb18(param_1,0x49);
    }
  }
  return;
}

