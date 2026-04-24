// Function: FUN_8022d4b0
// Entry: 8022d4b0
// Size: 1308 bytes

void FUN_8022d4b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  undefined4 uVar6;
  undefined2 *puVar7;
  int iVar8;
  int *piVar9;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar10;
  undefined8 extraout_f1_01;
  undefined8 extraout_f1_02;
  undefined8 extraout_f1_03;
  float local_18 [2];
  
  local_18[0] = FLOAT_803e7c58;
  iVar5 = (**(code **)(*DAT_803dd72c + 0x8c))();
  uVar10 = extraout_f1;
  if (*(int *)(param_10 + 4) == 0) {
    uVar6 = FUN_800381d8(param_9,0x606,local_18);
    *(undefined4 *)(param_10 + 4) = uVar6;
    uVar10 = extraout_f1_00;
    if (*(int *)(param_10 + 4) != 0) {
      uVar10 = FUN_80037e24(param_9,*(int *)(param_10 + 4),0);
    }
  }
  if (*(char *)(param_10 + 0x480) != '\0') {
    if (*(int *)(param_10 + 0x10) == 0) {
      uVar6 = FUN_800381d8(param_9,0x611,local_18);
      *(undefined4 *)(param_10 + 0x10) = uVar6;
      uVar10 = extraout_f1_01;
      if (*(int *)(param_10 + 0x10) != 0) {
        uVar10 = FUN_80037e24(param_9,*(int *)(param_10 + 0x10),0);
      }
    }
    if (*(int *)(param_10 + 8) == 0) {
      uVar6 = FUN_800381d8(param_9,0x610,local_18);
      *(undefined4 *)(param_10 + 8) = uVar6;
      uVar10 = extraout_f1_02;
      if (*(int *)(param_10 + 8) != 0) {
        uVar10 = FUN_80037e24(param_9,*(int *)(param_10 + 8),0);
      }
    }
    if (*(int *)(param_10 + 0xc) == 0) {
      uVar6 = FUN_800381d8(param_9,0x615,local_18);
      *(undefined4 *)(param_10 + 0xc) = uVar6;
      uVar10 = extraout_f1_03;
      if (*(int *)(param_10 + 0xc) != 0) {
        uVar10 = FUN_80037e24(param_9,*(int *)(param_10 + 0xc),0);
      }
    }
  }
  if ((*(int *)(param_10 + 0x418) == 0) && (*(int *)(param_10 + 0x41c) == 0)) {
    puVar7 = FUN_8002becc(0x20,0x6de);
    *(undefined *)(puVar7 + 2) = 1;
    *(undefined *)((int)puVar7 + 5) = 1;
    iVar8 = FUN_8002b678(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar7);
    *(int *)(param_10 + 0x418) = iVar8;
    puVar7 = FUN_8002becc(0x20,0x6de);
    *(undefined *)(puVar7 + 2) = 1;
    *(undefined *)((int)puVar7 + 5) = 1;
    iVar8 = FUN_8002b678(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         puVar7);
    *(int *)(param_10 + 0x41c) = iVar8;
  }
  bVar1 = false;
  if (*(char *)(param_10 + 0x480) == '\0') {
    if (*(int *)(param_10 + 4) != 0) {
      bVar1 = true;
    }
  }
  else {
    if (*(int *)(param_10 + 0x450) == 0) {
      piVar9 = FUN_8001f58c(param_9,'\x01');
      *(int **)(param_10 + 0x450) = piVar9;
      if (*(int *)(param_10 + 0x450) != 0) {
        FUN_8001dbf0(*(int *)(param_10 + 0x450),2);
        FUN_8001de4c((double)FLOAT_803e7b64,(double)FLOAT_803e7c5c,(double)FLOAT_803e7c60,
                     *(int **)(param_10 + 0x450));
        FUN_8001dbd8(*(int *)(param_10 + 0x450),1);
        FUN_8001dbb4(*(int *)(param_10 + 0x450),0x28,0x7d,0xff,0);
        FUN_8001dcfc((double)FLOAT_803e7c64,(double)FLOAT_803e7c68,*(int *)(param_10 + 0x450));
        FUN_8001d6e4(*(int *)(param_10 + 0x450),1,1);
        FUN_8001db7c(*(int *)(param_10 + 0x450),0x14,100,200,0);
      }
    }
    if ((((*(int *)(param_10 + 4) != 0) && (*(int *)(param_10 + 0x10) != 0)) &&
        (*(int *)(param_10 + 8) != 0)) && (*(int *)(param_10 + 0xc) != 0)) {
      bVar1 = true;
    }
  }
  if (bVar1) {
    (**(code **)(*DAT_803dd6d0 + 0x28))(param_9,0);
    *(byte *)(param_10 + 0x477) = *(byte *)(param_10 + 0x477) | 1;
    *(float *)(param_10 + 0x54) = FLOAT_803e7c08;
    fVar2 = FLOAT_803e7c0c;
    *(float *)(param_10 + 0x60) = FLOAT_803e7c0c;
    fVar3 = FLOAT_803e7c10;
    *(float *)(param_10 + 0x58) = FLOAT_803e7c10;
    fVar4 = FLOAT_803e7c14;
    *(float *)(param_10 + 100) = FLOAT_803e7c14;
    *(float *)(param_10 + 0x5c) = fVar3;
    *(float *)(param_10 + 0x68) = fVar4;
    *(float *)(param_10 + 0x78) = FLOAT_803e7c18;
    *(float *)(param_10 + 0x84) = FLOAT_803e7c1c;
    *(float *)(param_10 + 0x6c) = FLOAT_803e7b68;
    *(float *)(param_10 + 0x348) = FLOAT_803e7c20;
    *(float *)(param_10 + 0x34c) = fVar2;
    *(float *)(param_10 + 0x35c) = FLOAT_803e7c24;
    *(float *)(param_10 + 0x360) = fVar4;
    *(float *)(param_10 + 0x370) = FLOAT_803e7c28;
    *(float *)(param_10 + 0x374) = FLOAT_803e7c2c;
    *(float *)(param_10 + 900) = FLOAT_803e7c30;
    *(float *)(param_10 + 0x388) = FLOAT_803e7c34;
    *(float *)(param_10 + 0x394) = FLOAT_803e7c38;
    *(float *)(param_10 + 0x390) = FLOAT_803e7c3c;
    *(float *)(param_10 + 0x39c) = FLOAT_803e7c40;
    *(undefined *)(param_10 + 0x3fa) = 0x19;
    *(float *)(param_10 + 0x3a4) = FLOAT_803e7c44;
    fVar4 = FLOAT_803e7c48;
    *(float *)(param_10 + 0x38) = FLOAT_803e7c48;
    *(float *)(param_9 + 8) = fVar4;
    *(float *)(param_10 + 0x3ac) = FLOAT_803e7c4c;
    *(float *)(param_10 + 0x3b0) = FLOAT_803e7c50;
    *(float *)(param_10 + 0x88) = FLOAT_803e7c54;
    *(float *)(param_10 + 0x8c) = FLOAT_803e7bfc;
    *(float *)(param_10 + 0x90) = FLOAT_803e7c6c;
    *(float *)(param_10 + 0x94) = fVar2;
    *(float *)(param_10 + 0x98) = FLOAT_803e7c70;
    *(float *)(param_10 + 0xb8) = FLOAT_803e7c74;
    *(float *)(param_10 + 0xa0) = FLOAT_803e7c78;
    *(float *)(param_10 + 0xa8) = FLOAT_803e7bc4;
    *(undefined4 *)(param_10 + 0x9c) = *(undefined4 *)(param_10 + 0xa0);
    *(undefined4 *)(param_10 + 0xa4) = *(undefined4 *)(param_10 + 0xa8);
    fVar2 = FLOAT_803e7bf4;
    *(float *)(param_10 + 0xac) = FLOAT_803e7bf4;
    *(float *)(param_10 + 0xb0) = fVar2;
    if (*(char *)(param_9 + 0xac) == '&') {
      *(float *)(param_10 + 0x50) = FLOAT_803e7b64;
    }
    else {
      *(float *)(param_10 + 0x50) = fVar3;
    }
    *(undefined2 *)(param_10 + 0x40e) = 0x28;
    *(float *)(param_10 + 0x410) = FLOAT_803e7c78;
    *(undefined2 *)(param_10 + 0x40c) = 6;
    *(undefined2 *)(param_10 + 0x446) = 0x5a;
    *(float *)(param_10 + 0x448) = FLOAT_803e7bcc;
    *(undefined2 *)(param_10 + 0x444) = 0xc;
    *(undefined *)(param_10 + 0x44d) = 3;
    iVar8 = FUN_800396d0(param_9,0);
    *(int *)(param_10 + 0x454) = iVar8;
    iVar8 = FUN_800396d0(param_9,1);
    *(int *)(param_10 + 0x458) = iVar8;
    iVar8 = FUN_800396d0(param_9,2);
    *(int *)(param_10 + 0x45c) = iVar8;
    iVar8 = FUN_800396d0(param_9,3);
    *(int *)(param_10 + 0x460) = iVar8;
    *(float *)(param_10 + 0x464) = FLOAT_803e7bfc;
    *(undefined2 *)(param_10 + 0x44e) = 0xaf;
    *(undefined *)(param_10 + 0x469) = *(undefined *)(iVar5 + 1);
    *(undefined *)(param_10 + 0x468) = *(undefined *)(param_10 + 0x469);
    *(float *)(param_10 + 0x3b4) = FLOAT_803e7b90;
    fVar2 = FLOAT_803e7b88;
    *(float *)(param_10 + 0x3b8) = FLOAT_803e7b88;
    *(float *)(param_10 + 0x3bc) = FLOAT_803e7c7c;
    *(float *)(param_10 + 0x3c4) = FLOAT_803e7b8c;
    *(float *)(param_10 + 0x3c8) = FLOAT_803e7c6c;
    *(float *)(param_10 + 0x3d0) = FLOAT_803e7c80;
    *(float *)(param_10 + 0x3d4) = FLOAT_803e7c18;
    *(float *)(param_10 + 0x3e0) = FLOAT_803e7c3c;
    *(undefined4 *)(param_10 + 0x14) = *(undefined4 *)(param_9 + 0xc);
    *(undefined4 *)(param_10 + 0x18) = *(undefined4 *)(param_9 + 0x10);
    *(undefined4 *)(param_10 + 0x1c) = *(undefined4 *)(param_9 + 0x14);
    *(float *)(param_10 + 0x20) = FLOAT_803e7c84;
    *(float *)(param_10 + 0x28) = FLOAT_803e7c88;
    *(float *)(param_10 + 0x24) = fVar2;
  }
  return;
}

