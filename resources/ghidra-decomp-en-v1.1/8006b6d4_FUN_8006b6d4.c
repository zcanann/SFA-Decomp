// Function: FUN_8006b6d4
// Entry: 8006b6d4
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x8006b990) */
/* WARNING: Removing unreachable block (ram,0x8006b988) */
/* WARNING: Removing unreachable block (ram,0x8006b980) */
/* WARNING: Removing unreachable block (ram,0x8006b978) */
/* WARNING: Removing unreachable block (ram,0x8006b970) */
/* WARNING: Removing unreachable block (ram,0x8006b704) */
/* WARNING: Removing unreachable block (ram,0x8006b6fc) */
/* WARNING: Removing unreachable block (ram,0x8006b6f4) */
/* WARNING: Removing unreachable block (ram,0x8006b6ec) */
/* WARNING: Removing unreachable block (ram,0x8006b6e4) */

void FUN_8006b6d4(ushort *param_1)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float fStack_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float afStack_90 [15];
  
  FUN_8002b554(param_1,afStack_90,'\0');
  FUN_8000eba8((double)(*(float *)(param_1 + 6) - FLOAT_803dda58),(double)*(float *)(param_1 + 8),
               (double)(*(float *)(param_1 + 10) - FLOAT_803dda5c),
               (double)(FLOAT_803df98c * *(float *)(param_1 + 0x54) * *(float *)(param_1 + 4)),
               &local_94,&local_98,&local_9c,&local_a0,&local_a4,&fStack_a8);
  local_a0 = FLOAT_803df994 * local_a0 + FLOAT_803df990;
  local_a4 = FLOAT_803df998 * local_a4 + FLOAT_803df990;
  fVar1 = local_a4;
  if (local_a4 < local_a0) {
    fVar1 = local_a0;
  }
  dVar7 = (double)(FLOAT_803df99c / fVar1);
  dVar6 = (double)(float)((double)*(float *)(param_1 + 4) * dVar7);
  dVar4 = -(double)local_94;
  dVar8 = (double)local_98;
  FUN_8025da64((double)(float)((double)FLOAT_803df994 * dVar4),
               (double)(float)((double)FLOAT_803df998 * dVar8),(double)FLOAT_803df9a0,
               (double)FLOAT_803df9a4,(double)FLOAT_803df9a8,(double)FLOAT_803df9ac);
  if (FLOAT_803df9a8 <= local_9c) {
    **(float **)(param_1 + 0x32) = FLOAT_803df9a8;
  }
  else {
    dVar5 = (double)*(float *)(param_1 + 4);
    *(float *)(param_1 + 4) = (float)dVar6;
    FUN_80041e20(1);
    FUN_8003ba50(0,0,0,0,(int)param_1,1);
    FUN_80041e20(0);
    *(float *)(param_1 + 4) = (float)dVar5;
    iVar2 = FUN_8002b660((int)param_1);
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    FUN_8007048c(1,3,1);
    FUN_80259400(0x100,0xb0,0x80,0x80);
    FUN_80259504(0x80,0x80,0x2a,0);
    FUN_80259c0c((&DAT_8038ee3c)[DAT_803ddc0c] + 0x60,1);
    FUN_8006a1a4((&DAT_8038ee3c)[(DAT_803ddc0c + 1) % 3],0x80,0x10,0);
    **(float **)(param_1 + 0x32) = (float)((double)FLOAT_803df9ac / dVar7);
  }
  FUN_8000f7a0();
  dVar6 = (double)FLOAT_803df994;
  *(float *)(*(int *)(param_1 + 0x32) + 0x14) = (float)(dVar6 * -dVar4);
  dVar4 = (double)FLOAT_803df998;
  *(float *)(*(int *)(param_1 + 0x32) + 0x18) = (float)(dVar4 * -dVar8);
  *(float *)(*(int *)(param_1 + 0x32) + 0x14) =
       (float)((double)*(float *)(*(int *)(param_1 + 0x32) + 0x14) + dVar6);
  *(float *)(*(int *)(param_1 + 0x32) + 0x18) =
       (float)((double)*(float *)(*(int *)(param_1 + 0x32) + 0x18) + dVar4);
  fVar1 = FLOAT_803df99c;
  pfVar3 = *(float **)(param_1 + 0x32);
  pfVar3[5] = -(FLOAT_803df99c * *pfVar3 - pfVar3[5]);
  pfVar3 = *(float **)(param_1 + 0x32);
  pfVar3[6] = -(fVar1 * *pfVar3 - pfVar3[6]);
  return;
}

