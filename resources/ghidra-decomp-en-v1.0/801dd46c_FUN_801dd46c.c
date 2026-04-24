// Function: FUN_801dd46c
// Entry: 801dd46c
// Size: 1048 bytes

void FUN_801dd46c(undefined2 *param_1)

{
  ushort uVar1;
  short sVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  undefined uVar7;
  undefined4 *puVar6;
  undefined2 *puVar8;
  float *pfVar9;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  undefined auStack72 [4];
  undefined auStack68 [4];
  undefined auStack64 [4];
  undefined auStack60 [12];
  float local_30;
  undefined auStack44 [4];
  float local_28 [2];
  double local_20;
  
  pfVar9 = *(float **)(param_1 + 0x5c);
  iVar4 = FUN_80036770(param_1,auStack64,auStack68,auStack72,&local_30,auStack44,local_28);
  if (((*(char *)((int)param_1 + 0xad) == '\x05') || (iVar5 = FUN_8001ffb4(0x639), iVar5 != 0)) ||
     (iVar5 = FUN_8001ffb4(0xc10), iVar5 == 0)) {
    if (iVar4 == 0) {
      return;
    }
    if (iVar4 == 0x11) {
      return;
    }
    FUN_8000bb18(param_1,0x138);
    local_30 = local_30 + FLOAT_803dcdd8;
    local_28[0] = local_28[0] + FLOAT_803dcddc;
    FUN_8009a1dc((double)FLOAT_803e5618,param_1,auStack60,1,0);
    return;
  }
  if ((iVar4 != 0) && (iVar4 != 0x11)) {
    FUN_8000bb18(param_1,0x138);
    local_30 = local_30 + FLOAT_803dcdd8;
    local_28[0] = local_28[0] + FLOAT_803dcddc;
    FUN_8009a1dc((double)FLOAT_803e5618,param_1,auStack60,1,0);
    *(ushort *)((int)pfVar9 + 0x12) = *(ushort *)((int)pfVar9 + 0x12) ^ 2;
    if ((*(ushort *)((int)pfVar9 + 0x12) & 2) == 0) {
      iVar4 = FUN_8002e0fc(&local_58,&local_54);
      fVar3 = FLOAT_803e5620;
      for (; local_58 < local_54; local_58 = local_58 + 1) {
        puVar8 = *(undefined2 **)(iVar4 + local_58 * 4);
        if ((puVar8[0x23] == 0x3c1) && (puVar8 != param_1)) {
          *(float *)(*(int *)(puVar8 + 0x5c) + 8) = *(float *)(*(int *)(puVar8 + 0x5c) + 8) + fVar3;
        }
      }
      puVar6 = (undefined4 *)FUN_800394ac(param_1,0,0);
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0;
      }
    }
    else {
      if (*pfVar9 != FLOAT_803e55f4) {
        uVar7 = FUN_801dd1a8(param_1,pfVar9);
        FUN_800200e8(0x639,uVar7);
      }
      iVar4 = FUN_8002e0fc(&local_50,&local_4c);
      fVar3 = FLOAT_803e561c;
      for (; local_50 < local_4c; local_50 = local_50 + 1) {
        puVar8 = *(undefined2 **)(iVar4 + local_50 * 4);
        if ((puVar8[0x23] == 0x3c1) && (puVar8 != param_1)) {
          *(float *)(*(int *)(puVar8 + 0x5c) + 8) = *(float *)(*(int *)(puVar8 + 0x5c) + 8) + fVar3;
        }
      }
    }
  }
  uVar1 = *(ushort *)((int)pfVar9 + 0x12);
  if ((uVar1 & 2) != 0) {
    return;
  }
  if ((uVar1 & 4) == 0) {
    if ((uVar1 & 1) != 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar9 + 4) + 1U ^ 0x80000000);
      if (FLOAT_803e55f0 * (float)(local_20 - DOUBLE_803e5610) < pfVar9[3]) {
        pfVar9[3] = -(FLOAT_803e5628 * pfVar9[2] * FLOAT_803db414 - pfVar9[3]);
        goto LAB_801dd850;
      }
    }
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar9 + 4) ^ 0x80000000);
    if (FLOAT_803e55f0 * (float)(local_20 - DOUBLE_803e5610) <= pfVar9[3]) {
      *pfVar9 = pfVar9[1] / pfVar9[2];
      *(ushort *)((int)pfVar9 + 0x12) = *(ushort *)((int)pfVar9 + 0x12) | 4;
    }
    else {
      pfVar9[3] = FLOAT_803e5628 * pfVar9[2] * FLOAT_803db414 + pfVar9[3];
    }
  }
  else {
    *pfVar9 = *pfVar9 - FLOAT_803db414;
    if (*pfVar9 < FLOAT_803e55f4) {
      *(ushort *)((int)pfVar9 + 0x12) = *(ushort *)((int)pfVar9 + 0x12) & 0xfffb;
      FUN_8000b4d0(param_1,0x137,2);
      if ((*(ushort *)((int)pfVar9 + 0x12) & 1) == 0) {
        sVar2 = *(short *)(pfVar9 + 4);
        *(short *)(pfVar9 + 4) = sVar2 + 1;
        if (7 < (short)(sVar2 + 1)) {
          pfVar9[3] = pfVar9[3] - FLOAT_803e5624;
          *(undefined2 *)(pfVar9 + 4) = 0;
        }
      }
      else {
        sVar2 = *(short *)(pfVar9 + 4);
        *(short *)(pfVar9 + 4) = sVar2 + -1;
        if ((short)(sVar2 + -1) < 0) {
          pfVar9[3] = pfVar9[3] + FLOAT_803e5624;
          *(undefined2 *)(pfVar9 + 4) = 7;
        }
      }
    }
  }
LAB_801dd850:
  *param_1 = (short)(int)pfVar9[3];
  return;
}

