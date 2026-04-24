// Function: FUN_80205830
// Entry: 80205830
// Size: 608 bytes

void FUN_80205830(int param_1)

{
  float fVar1;
  int iVar2;
  short sVar3;
  char in_r8;
  int iVar4;
  double dVar5;
  undefined auStack120 [8];
  undefined auStack112 [8];
  undefined auStack104 [8];
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  undefined auStack60 [12];
  float local_30;
  float local_2c;
  float local_28;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar4 + 4) = 0;
    *(undefined *)(iVar4 + 8) = 0;
  }
  else {
    FUN_8003b8f4((double)FLOAT_803e63c8);
    if (*(char *)(iVar4 + 10) != '\0') {
      *(undefined *)(iVar4 + 8) = 1;
      iVar2 = FUN_8000faac();
      local_48 = *(float *)(iVar2 + 0xc) - *(float *)(param_1 + 0xc);
      local_44 = *(float *)(iVar2 + 0x10) - *(float *)(param_1 + 0x10);
      local_40 = *(float *)(iVar2 + 0x14) - *(float *)(param_1 + 0x14);
      dVar5 = (double)FUN_802931a0((double)(local_40 * local_40 +
                                           local_48 * local_48 + local_44 * local_44));
      if ((double)FLOAT_803e63cc < dVar5) {
        fVar1 = (float)((double)FLOAT_803e63c8 / dVar5);
        local_48 = local_48 * fVar1;
        local_44 = local_44 * fVar1;
        local_40 = local_40 * fVar1;
        local_54 = FLOAT_803e63d0 * local_48 + *(float *)(param_1 + 0xc);
        local_50 = FLOAT_803e63d0 * local_44 + *(float *)(param_1 + 0x10);
        local_4c = FLOAT_803e63d0 * local_40 + *(float *)(param_1 + 0x14);
        local_60 = FLOAT_803e63d4 * local_48 + *(float *)(iVar2 + 0xc);
        local_5c = FLOAT_803e63d4 * local_44 + *(float *)(iVar2 + 0x10);
        local_58 = FLOAT_803e63d4 * local_40 + *(float *)(iVar2 + 0x14);
        FUN_80012d00(&local_54,auStack104);
        FUN_80012d00(&local_60,auStack112);
        iVar2 = FUN_800128dc(auStack104,auStack112,auStack120,0,0);
        if (iVar2 == 0) {
          *(undefined *)(iVar4 + 8) = 0;
          (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        }
      }
      if (*(short *)(iVar4 + 4) < 1) {
        if (*(char *)(iVar4 + 8) != '\0') {
          local_30 = FLOAT_803e63d8;
          local_2c = FLOAT_803e63dc;
          local_28 = FLOAT_803e63d8;
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x1f7,auStack60,0x12,0xffffffff,0);
        }
        sVar3 = FUN_800221a0(0xfffffff6,10);
        *(short *)(iVar4 + 4) = sVar3 + 0x3c;
      }
      else {
        *(short *)(iVar4 + 4) = *(short *)(iVar4 + 4) - (short)(int)FLOAT_803db414;
      }
    }
  }
  return;
}

