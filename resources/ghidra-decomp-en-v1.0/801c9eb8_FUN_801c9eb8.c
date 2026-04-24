// Function: FUN_801c9eb8
// Entry: 801c9eb8
// Size: 588 bytes

void FUN_801c9eb8(int param_1)

{
  float fVar1;
  int iVar2;
  short sVar3;
  char in_r8;
  int iVar4;
  double dVar5;
  undefined auStack104 [8];
  undefined auStack96 [8];
  undefined auStack88 [8];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack44 [12];
  float local_20;
  float local_1c;
  float local_18;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar4 + 4) = 0;
    *(undefined *)(iVar4 + 10) = 0;
  }
  else if (*(char *)(iVar4 + 0xc) != '\0') {
    *(undefined *)(iVar4 + 10) = 1;
    iVar2 = FUN_8000faac();
    local_38 = *(float *)(iVar2 + 0xc) - *(float *)(param_1 + 0xc);
    local_34 = *(float *)(iVar2 + 0x10) - *(float *)(param_1 + 0x10);
    local_30 = *(float *)(iVar2 + 0x14) - *(float *)(param_1 + 0x14);
    dVar5 = (double)FUN_802931a0((double)(local_30 * local_30 +
                                         local_38 * local_38 + local_34 * local_34));
    if ((double)FLOAT_803e5120 < dVar5) {
      fVar1 = (float)((double)FLOAT_803e5124 / dVar5);
      local_38 = local_38 * fVar1;
      local_34 = local_34 * fVar1;
      local_30 = local_30 * fVar1;
      local_44 = FLOAT_803e5128 * local_38 + *(float *)(param_1 + 0xc);
      local_40 = FLOAT_803e5128 * local_34 + *(float *)(param_1 + 0x10);
      local_3c = FLOAT_803e5128 * local_30 + *(float *)(param_1 + 0x14);
      local_50 = FLOAT_803e512c * local_38 + *(float *)(iVar2 + 0xc);
      local_4c = FLOAT_803e512c * local_34 + *(float *)(iVar2 + 0x10);
      local_48 = FLOAT_803e512c * local_30 + *(float *)(iVar2 + 0x14);
      FUN_80012d00(&local_44,auStack88);
      FUN_80012d00(&local_50,auStack96);
      iVar2 = FUN_800128dc(auStack88,auStack96,auStack104,0,0);
      if (iVar2 == 0) {
        *(undefined *)(iVar4 + 10) = 0;
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
      }
    }
    if (*(short *)(iVar4 + 4) < 1) {
      if (*(char *)(iVar4 + 10) != '\0') {
        local_20 = FLOAT_803e5130;
        local_1c = FLOAT_803e5134;
        local_18 = FLOAT_803e5130;
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x1f7,auStack44,0x12,0xffffffff,0);
      }
      sVar3 = FUN_800221a0(0xfffffff6,10);
      *(short *)(iVar4 + 4) = sVar3 + 0x3c;
    }
    else {
      *(ushort *)(iVar4 + 4) = *(short *)(iVar4 + 4) - (ushort)DAT_803db410;
    }
  }
  return;
}

