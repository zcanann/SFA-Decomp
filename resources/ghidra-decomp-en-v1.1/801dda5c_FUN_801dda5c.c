// Function: FUN_801dda5c
// Entry: 801dda5c
// Size: 1048 bytes

void FUN_801dda5c(undefined2 *param_1)

{
  ushort uVar1;
  short sVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined2 *puVar7;
  float *pfVar8;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  uint uStack_48;
  int iStack_44;
  undefined4 uStack_40;
  undefined auStack_3c [12];
  float local_30;
  undefined4 uStack_2c;
  float local_28 [2];
  undefined8 local_20;
  
  pfVar8 = *(float **)(param_1 + 0x5c);
  iVar4 = FUN_80036868((int)param_1,&uStack_40,&iStack_44,&uStack_48,&local_30,&uStack_2c,local_28);
  if (((*(char *)((int)param_1 + 0xad) == '\x05') || (uVar5 = FUN_80020078(0x639), uVar5 != 0)) ||
     (uVar5 = FUN_80020078(0xc10), uVar5 == 0)) {
    if (iVar4 == 0) {
      return;
    }
    if (iVar4 == 0x11) {
      return;
    }
    FUN_8000bb38((uint)param_1,0x138);
    local_30 = local_30 + FLOAT_803dda58;
    local_28[0] = local_28[0] + FLOAT_803dda5c;
    FUN_8009a468(param_1,auStack_3c,1,(int *)0x0);
    return;
  }
  if ((iVar4 != 0) && (iVar4 != 0x11)) {
    FUN_8000bb38((uint)param_1,0x138);
    local_30 = local_30 + FLOAT_803dda58;
    local_28[0] = local_28[0] + FLOAT_803dda5c;
    FUN_8009a468(param_1,auStack_3c,1,(int *)0x0);
    *(ushort *)((int)pfVar8 + 0x12) = *(ushort *)((int)pfVar8 + 0x12) ^ 2;
    if ((*(ushort *)((int)pfVar8 + 0x12) & 2) == 0) {
      iVar4 = FUN_8002e1f4(&local_58,&local_54);
      fVar3 = FLOAT_803e62b8;
      for (; local_58 < local_54; local_58 = local_58 + 1) {
        puVar7 = *(undefined2 **)(iVar4 + local_58 * 4);
        if ((puVar7[0x23] == 0x3c1) && (puVar7 != param_1)) {
          *(float *)(*(int *)(puVar7 + 0x5c) + 8) = *(float *)(*(int *)(puVar7 + 0x5c) + 8) + fVar3;
        }
      }
      puVar6 = (undefined4 *)FUN_800395a4((int)param_1,0);
      if (puVar6 != (undefined4 *)0x0) {
        *puVar6 = 0;
      }
    }
    else {
      if (*pfVar8 != FLOAT_803e628c) {
        uVar5 = FUN_801dd798();
        FUN_800201ac(0x639,uVar5 & 0xff);
      }
      iVar4 = FUN_8002e1f4(&local_50,&local_4c);
      fVar3 = FLOAT_803e62b4;
      for (; local_50 < local_4c; local_50 = local_50 + 1) {
        puVar7 = *(undefined2 **)(iVar4 + local_50 * 4);
        if ((puVar7[0x23] == 0x3c1) && (puVar7 != param_1)) {
          *(float *)(*(int *)(puVar7 + 0x5c) + 8) = *(float *)(*(int *)(puVar7 + 0x5c) + 8) + fVar3;
        }
      }
    }
  }
  uVar1 = *(ushort *)((int)pfVar8 + 0x12);
  if ((uVar1 & 2) != 0) {
    return;
  }
  if ((uVar1 & 4) == 0) {
    if ((uVar1 & 1) != 0) {
      local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar8 + 4) + 1U ^ 0x80000000);
      if (FLOAT_803e6288 * (float)(local_20 - DOUBLE_803e62a8) < pfVar8[3]) {
        pfVar8[3] = -(FLOAT_803e62c0 * pfVar8[2] * FLOAT_803dc074 - pfVar8[3]);
        goto LAB_801dde40;
      }
    }
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(pfVar8 + 4) ^ 0x80000000);
    if (FLOAT_803e6288 * (float)(local_20 - DOUBLE_803e62a8) <= pfVar8[3]) {
      *pfVar8 = pfVar8[1] / pfVar8[2];
      *(ushort *)((int)pfVar8 + 0x12) = *(ushort *)((int)pfVar8 + 0x12) | 4;
    }
    else {
      pfVar8[3] = FLOAT_803e62c0 * pfVar8[2] * FLOAT_803dc074 + pfVar8[3];
    }
  }
  else {
    *pfVar8 = *pfVar8 - FLOAT_803dc074;
    if (*pfVar8 < FLOAT_803e628c) {
      *(ushort *)((int)pfVar8 + 0x12) = *(ushort *)((int)pfVar8 + 0x12) & 0xfffb;
      FUN_8000b4f0((uint)param_1,0x137,2);
      if ((*(ushort *)((int)pfVar8 + 0x12) & 1) == 0) {
        sVar2 = *(short *)(pfVar8 + 4);
        *(short *)(pfVar8 + 4) = sVar2 + 1;
        if (7 < (short)(sVar2 + 1)) {
          pfVar8[3] = pfVar8[3] - FLOAT_803e62bc;
          *(undefined2 *)(pfVar8 + 4) = 0;
        }
      }
      else {
        sVar2 = *(short *)(pfVar8 + 4);
        *(short *)(pfVar8 + 4) = sVar2 + -1;
        if ((short)(sVar2 + -1) < 0) {
          pfVar8[3] = pfVar8[3] + FLOAT_803e62bc;
          *(undefined2 *)(pfVar8 + 4) = 7;
        }
      }
    }
  }
LAB_801dde40:
  *param_1 = (short)(int)pfVar8[3];
  return;
}

