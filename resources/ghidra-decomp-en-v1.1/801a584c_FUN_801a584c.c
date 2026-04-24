// Function: FUN_801a584c
// Entry: 801a584c
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x801a5bac) */
/* WARNING: Removing unreachable block (ram,0x801a585c) */

int FUN_801a584c(ushort *param_1,float *param_2)

{
  int iVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  double dVar5;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float local_54;
  undefined4 local_50;
  uint uStack_4c;
  longlong local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  undefined4 local_30;
  uint uStack_2c;
  longlong local_28;
  
  dVar5 = (double)FLOAT_803e5088;
  FUN_8002b2c0(param_1,param_2,&local_68,'\0');
  *(float *)(param_1 + 0x12) = FLOAT_803dc074 * param_2[0xc] + *(float *)(param_1 + 0x12);
  *(float *)(param_1 + 0x14) = FLOAT_803dc074 * param_2[0xd] + *(float *)(param_1 + 0x14);
  *(float *)(param_1 + 0x16) = FLOAT_803dc074 * param_2[0xe] + *(float *)(param_1 + 0x16);
  param_2[6] = FLOAT_803dc074 * param_2[9] + param_2[6];
  param_2[7] = FLOAT_803dc074 * param_2[10] + param_2[7];
  param_2[8] = FLOAT_803dc074 * param_2[0xb] + param_2[8];
  fVar3 = FLOAT_803e5088;
  if (param_2[0x15] <= local_64) {
    *(byte *)((int)param_2 + 0x66) = *(byte *)((int)param_2 + 0x66) & 0xfb;
  }
  else {
    if (((*(float *)(param_1 + 0x14) < FLOAT_803e5088) &&
        ((*(byte *)((int)param_2 + 0x66) & 4) != 0)) ||
       (FLOAT_803e5088 == *(float *)(param_1 + 0x14))) {
      param_2[0xd] = FLOAT_803e5088;
      param_2[0xb] = fVar3;
      param_2[8] = fVar3;
      param_2[10] = fVar3;
      param_2[7] = fVar3;
      param_2[9] = fVar3;
      param_2[6] = fVar3;
      *(float *)(param_1 + 0x14) = fVar3;
      fVar2 = FLOAT_803e50b0;
      param_2[0xc] = param_2[0xc] * FLOAT_803e50b0;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * fVar2;
      param_2[0xe] = param_2[0xe] * fVar2;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar2;
      fVar2 = *(float *)(param_1 + 0x12);
      if (fVar2 < fVar3) {
        fVar2 = -fVar2;
      }
      if (fVar2 < FLOAT_803e50b4) {
        fVar3 = *(float *)(param_1 + 0x16);
        if (fVar3 < FLOAT_803e5088) {
          fVar3 = -fVar3;
        }
        if (fVar3 < FLOAT_803e50b4) {
          dVar5 = (double)FLOAT_803e508c;
        }
      }
    }
    if (*(float *)(param_1 + 0x14) < FLOAT_803e5088) {
      *(float *)(param_1 + 0x14) = FLOAT_803e50b8 * -*(float *)(param_1 + 0x14);
      fVar3 = FLOAT_803e50b0;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e50b0;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
      param_2[0xd] = FLOAT_803e50bc;
      param_2[0xb] = -param_2[0xb];
    }
    *(byte *)((int)param_2 + 0x66) = *(byte *)((int)param_2 + 0x66) | 4;
  }
  dVar4 = DOUBLE_803e50a8;
  uStack_4c = (int)(short)*param_1 ^ 0x80000000;
  local_50 = 0x43300000;
  iVar1 = (int)(param_2[6] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e50a8));
  local_48 = (longlong)iVar1;
  *param_1 = (ushort)iVar1;
  uStack_3c = (int)(short)param_1[1] ^ 0x80000000;
  local_40 = 0x43300000;
  iVar1 = (int)(param_2[7] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar4));
  local_38 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  uStack_2c = (int)(short)param_1[2] ^ 0x80000000;
  local_30 = 0x43300000;
  iVar1 = (int)(param_2[8] * FLOAT_803dc074 +
               (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar4));
  local_28 = (longlong)iVar1;
  param_1[2] = (ushort)iVar1;
  FUN_8002b2c0(param_1,param_2,&local_5c,'\0');
  *(float *)(param_1 + 6) = *(float *)(param_1 + 6) + (local_68 - local_5c);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + (local_64 - local_58);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 10) + (local_60 - local_54);
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  return (int)dVar5;
}

