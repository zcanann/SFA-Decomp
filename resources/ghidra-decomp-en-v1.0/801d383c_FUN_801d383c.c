// Function: FUN_801d383c
// Entry: 801d383c
// Size: 1520 bytes

void FUN_801d383c(short *param_1)

{
  uint uVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  undefined2 *puVar8;
  undefined auStack40 [4];
  undefined auStack36 [4];
  int local_20 [2];
  longlong local_18;
  
  puVar8 = *(undefined2 **)(param_1 + 0x5c);
  if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
    while (iVar6 = FUN_800374ec(param_1,local_20,auStack36,0), iVar6 != 0) {
      if (local_20[0] == 0x7000b) {
        FUN_8001ff3c(0x66c);
        FUN_8000bb18(param_1,0xa7);
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        iVar6 = 0;
        do {
          FUN_800972dc((double)FLOAT_803e53b0,(double)FLOAT_803e53b8,param_1,5,7,1,0x3c,0,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x3f3,0,4,0xffffffff,0);
          iVar6 = iVar6 + 1;
        } while (iVar6 < 10);
        FUN_8001db6c((double)FLOAT_803e53ac,*(undefined4 *)(puVar8 + 0x138),0);
        *(float *)(puVar8 + 0x152) = FLOAT_803e53bc;
        param_1[3] = param_1[3] | 0x4000;
        FUN_80035f00(param_1);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf;
      }
    }
    if ((*(byte *)(puVar8 + 0x158) >> 6 & 1) != 0) {
      return;
    }
  }
  fVar2 = FLOAT_803e5394;
  if (*(float *)(puVar8 + 0x152) == FLOAT_803e5394) {
    fVar2 = *(float *)(puVar8 + 0x13a);
    if (fVar2 < FLOAT_803e53c0) {
      uVar1 = (uint)-(FLOAT_803e53c8 * fVar2 - FLOAT_803e53c4);
      local_18 = (longlong)(int)uVar1;
      FUN_800972dc((double)FLOAT_803e53b0,
                   (double)(float)(DOUBLE_803e53d8 * (double)(FLOAT_803e53c0 - fVar2) +
                                  DOUBLE_803e53d0),param_1,5,7,1,uVar1 & 0xff,0,0);
    }
    FUN_8003687c(param_1,auStack40,0,0);
    iVar6 = **(int **)(param_1 + 0x2a);
    if (-1 < *(char *)(puVar8 + 0x158)) {
      *(float *)(puVar8 + 0x142) = *(float *)(puVar8 + 0x142) - FLOAT_803db414;
      if (*(float *)(puVar8 + 0x142) < FLOAT_803e5394) {
        *(float *)(puVar8 + 0x142) = FLOAT_803e5394;
      }
      *(float *)(puVar8 + 0x150) = *(float *)(puVar8 + 0x150) - FLOAT_803db414;
      if (*(float *)(puVar8 + 0x150) < FLOAT_803e5394) {
        *(float *)(puVar8 + 0x150) = FLOAT_803e5394;
      }
      *param_1 = *param_1 + puVar8[0x157];
      *(float *)(param_1 + 0x14) = FLOAT_803e53e0 * FLOAT_803db414 + *(float *)(param_1 + 0x14);
      if (*(float *)(param_1 + 0x14) < FLOAT_803e53e4) {
        *(float *)(param_1 + 0x14) = FLOAT_803e53e4;
      }
      if (FLOAT_803e5394 < *(float *)(param_1 + 0x14)) {
        *(float *)(param_1 + 0x14) = *(float *)(param_1 + 0x14) * FLOAT_803e53e8;
      }
      if (*(float *)(param_1 + 0x14) < FLOAT_803e5394) {
        FUN_80035f20(param_1);
      }
      FUN_801d359c(param_1,puVar8);
      iVar7 = FUN_800221a0(0,100);
      if ((iVar7 < 5) && (*(float *)(puVar8 + 0x142) <= FLOAT_803e5394)) {
        FUN_801d33d4(param_1,puVar8);
      }
      fVar2 = *(float *)(puVar8 + 0x14c) - FLOAT_803db414;
      *(float *)(puVar8 + 0x14c) = fVar2;
      fVar5 = FLOAT_803e53e8;
      fVar4 = FLOAT_803e5394;
      if (FLOAT_803e5394 < fVar2) {
        *(float *)(puVar8 + 0x13e) =
             FLOAT_803e53ec * (*(float *)(puVar8 + 0x14e) - *(float *)(puVar8 + 0x13e)) *
             FLOAT_803db414 + *(float *)(puVar8 + 0x13e);
      }
      else {
        *(float *)(puVar8 + 0x148) = *(float *)(puVar8 + 0x148) * FLOAT_803e53e8;
        *(float *)(puVar8 + 0x14a) = *(float *)(puVar8 + 0x14a) * fVar5;
        *(float *)(puVar8 + 0x14c) = fVar4;
      }
      *(float *)(param_1 + 0x12) =
           *(float *)(puVar8 + 0x148) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x144);
      *(float *)(param_1 + 0x16) =
           *(float *)(puVar8 + 0x14a) * *(float *)(puVar8 + 0x13e) + *(float *)(puVar8 + 0x146);
      FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                   (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
      (**(code **)(*DAT_803dcaa8 + 0x10))((double)FLOAT_803db414,param_1,puVar8 + 4);
      (**(code **)(*DAT_803dcaa8 + 0x14))(param_1,puVar8 + 4);
      (**(code **)(*DAT_803dcaa8 + 0x18))((double)FLOAT_803db414,param_1,puVar8 + 4);
      if ((((iVar6 != 0) && (sVar3 = *(short *)(iVar6 + 0x46), sVar3 != 0x36d)) && (sVar3 != 0x198))
         && (sVar3 != 0x63c)) {
        FUN_8000bb18(param_1,0x59);
        *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80;
        if (FLOAT_803e53c0 < *(float *)(puVar8 + 0x13a)) {
          *(float *)(puVar8 + 0x13a) = FLOAT_803e53c0;
        }
      }
      if (((*(byte *)(puVar8 + 0x134) & 0x11) != 0) &&
         (*(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0x7f | 0x80,
         FLOAT_803e53c0 < *(float *)(puVar8 + 0x13a))) {
        *(float *)(puVar8 + 0x13a) = FLOAT_803e53c0;
      }
    }
    iVar7 = FUN_8002b9ec();
    if (iVar6 == iVar7) {
      *puVar8 = 0x18e;
      FUN_800378c4(iVar6,0x7000a,param_1,puVar8);
      *(byte *)(puVar8 + 0x158) = *(byte *)(puVar8 + 0x158) & 0xbf | 0x40;
    }
    else {
      fVar2 = *(float *)(puVar8 + 0x13a) - FLOAT_803db414;
      *(float *)(puVar8 + 0x13a) = fVar2;
      if (fVar2 <= FLOAT_803e5394) {
        FUN_8000bb18(param_1,0xa2);
        (**(code **)(*DAT_803dca78 + 0x14))(param_1);
        iVar6 = 0;
        do {
          FUN_800972dc((double)FLOAT_803e53b0,(double)FLOAT_803e53b8,param_1,5,7,1,0x3c,0,0);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x3f3,0,4,0xffffffff,0);
          iVar6 = iVar6 + 1;
        } while (iVar6 < 10);
        FUN_8001db6c((double)FLOAT_803e53ac,*(undefined4 *)(puVar8 + 0x138),0);
        *(float *)(puVar8 + 0x152) = FLOAT_803e53bc;
        param_1[3] = param_1[3] | 0x4000;
        FUN_80035f00(param_1);
      }
    }
  }
  else {
    *param_1 = *param_1 + (ushort)DAT_803db410 * 0x40;
    *(float *)(puVar8 + 0x152) = *(float *)(puVar8 + 0x152) - FLOAT_803db414;
    if (*(float *)(puVar8 + 0x152) <= fVar2) {
      FUN_8002cbc4(param_1);
    }
  }
  return;
}

