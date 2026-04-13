// Function: FUN_801f0928
// Entry: 801f0928
// Size: 740 bytes

void FUN_801f0928(short *param_1)

{
  uint uVar1;
  short *psVar2;
  char cVar3;
  undefined4 *puVar4;
  
  uVar1 = FUN_80020078(0x78);
  if (uVar1 == 0) {
    if (param_1[0x23] == 0x188) {
      *(undefined *)(param_1 + 0x1b) = 0x80;
    }
    else {
      psVar2 = (short *)FUN_8002bac4();
      puVar4 = *(undefined4 **)(param_1 + 0x5c);
      uVar1 = FUN_80020078(0x429);
      if (uVar1 == 0) {
        uVar1 = FUN_80020078(0xd0);
        if ((uVar1 == 0) &&
           (cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),2),
           cVar3 == '\0')) {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),2);
        if (cVar3 != '\0') {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,0);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,0);
        }
      }
      uVar1 = FUN_80020078(0xd0);
      if (uVar1 == 0) {
        if ((*(char *)(puVar4 + 3) == '\0') && (uVar1 = FUN_80020078(0x429), uVar1 == 0)) {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),1,1);
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),2,1);
          *(undefined *)(puVar4 + 3) = 1;
        }
      }
      else {
        cVar3 = (**(code **)(*DAT_803dd72c + 0x4c))(*(undefined *)(param_1 + 0x1a),4);
        if (cVar3 == '\0') {
          (**(code **)(*DAT_803dd72c + 0x50))(*(undefined *)(param_1 + 0x1a),4,1);
        }
        if (*(char *)(puVar4 + 3) != '\0') {
          *(undefined *)(puVar4 + 3) = 0;
        }
      }
      uVar1 = FUN_80020078(0xa4);
      if (uVar1 == 0) {
        *(float *)(psVar2 + 6) = FLOAT_803e6984;
        *(float *)(psVar2 + 8) = FLOAT_803e6988;
        *(float *)(psVar2 + 10) = FLOAT_803e698c;
        FUN_80063000(psVar2,param_1,0);
        FUN_8029731c((int)psVar2);
        param_1[0x7c] = 0;
        param_1[0x7d] = 1;
      }
      else {
        param_1[0x7a] = 0;
        param_1[0x7b] = 10;
        if (*(int *)(param_1 + 0x7c) == 1) {
          *(undefined4 *)(param_1 + 6) = *puVar4;
          *(undefined4 *)(param_1 + 8) = puVar4[1];
          *(undefined4 *)(param_1 + 10) = puVar4[2];
          *param_1 = *(short *)((int)puVar4 + 0xe);
          (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
          param_1[0x7c] = 0;
          param_1[0x7d] = 2;
        }
      }
    }
  }
  return;
}

