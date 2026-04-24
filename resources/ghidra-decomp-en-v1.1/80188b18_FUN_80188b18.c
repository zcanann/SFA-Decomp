// Function: FUN_80188b18
// Entry: 80188b18
// Size: 468 bytes

/* WARNING: Removing unreachable block (ram,0x80188cc8) */
/* WARNING: Removing unreachable block (ram,0x80188b28) */

void FUN_80188b18(short *param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int *piVar5;
  int iVar6;
  float *pfVar7;
  double dVar8;
  int local_38;
  float local_34;
  float local_30;
  float local_2c;
  undefined4 local_28;
  uint uStack_24;
  
  sVar1 = param_1[0x23];
  if (((sVar1 == 0x7a1) || (sVar1 == 0x7a2)) || (sVar1 == 0x7a3)) {
    pfVar7 = *(float **)(param_1 + 0x5c);
    piVar5 = FUN_80037048(2,&local_38);
    for (; local_38 != 0; local_38 = local_38 + -1) {
      dVar8 = (double)FUN_800217c8((float *)(*piVar5 + 0x18),(float *)(param_1 + 0xc));
      if (dVar8 < (double)pfVar7[6]) {
        iVar6 = *(int *)(*piVar5 + 0x54);
        if (iVar6 != 0) {
          uStack_24 = (int)*(short *)(iVar6 + 0x5a) ^ 0x80000000;
          local_28 = 0x43300000;
          dVar8 = (double)(float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4818);
          FUN_8002b384(&local_34,param_1,(float *)(*piVar5 + 0xc));
          if (pfVar7[3] <= local_34) {
            fVar2 = FLOAT_803e4814;
            if (*pfVar7 < local_34) {
              fVar2 = local_34 - *pfVar7;
              fVar2 = fVar2 * fVar2;
            }
          }
          else {
            fVar2 = local_34 - pfVar7[3];
            fVar2 = fVar2 * fVar2;
          }
          if (pfVar7[4] <= local_30) {
            fVar3 = FLOAT_803e4814;
            if (pfVar7[1] < local_30) {
              fVar3 = local_30 - pfVar7[1];
              fVar3 = fVar3 * fVar3;
            }
          }
          else {
            fVar3 = local_30 - pfVar7[4];
            fVar3 = fVar3 * fVar3;
          }
          if (pfVar7[5] <= local_2c) {
            fVar4 = FLOAT_803e4814;
            if (pfVar7[2] < local_2c) {
              fVar4 = local_2c - pfVar7[2];
              fVar4 = fVar4 * fVar4;
            }
          }
          else {
            fVar4 = local_2c - pfVar7[5];
            fVar4 = fVar4 * fVar4;
          }
          if (FLOAT_803e4814 + fVar2 + fVar3 + fVar4 < (float)(dVar8 * dVar8)) {
            *(short **)(*(int *)(*piVar5 + 0x54) + 0x50) = param_1;
            *(undefined *)(*(int *)(*piVar5 + 0x54) + 0xad) = 1;
          }
        }
      }
      piVar5 = piVar5 + 1;
    }
  }
  return;
}

