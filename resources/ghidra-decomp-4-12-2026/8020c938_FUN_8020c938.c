// Function: FUN_8020c938
// Entry: 8020c938
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x8020caa0) */
/* WARNING: Removing unreachable block (ram,0x8020c948) */

void FUN_8020c938(short *param_1)

{
  int iVar1;
  short *psVar2;
  double dVar3;
  double dVar4;
  
  psVar2 = *(short **)(param_1 + 0x5c);
  iVar1 = FUN_8002e1ac(0x42fe7);
  *param_1 = *param_1 + psVar2[2];
  param_1[1] = param_1[1] + psVar2[1];
  param_1[2] = param_1[2] + *psVar2;
  psVar2[3] = psVar2[3] + (short)(0x9c4 / (int)psVar2[4]);
  dVar3 = (double)FUN_80293eac();
  dVar4 = (double)FUN_80293994();
  *(float *)(param_1 + 6) =
       (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (int)psVar2[4] ^ 0x80000000) -
                                              DOUBLE_803e7270) * dVar4) * dVar3 +
              (double)*(float *)(iVar1 + 0xc));
  dVar3 = (double)FUN_80293994();
  dVar4 = (double)FUN_80293994();
  *(float *)(param_1 + 8) =
       (float)((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                (int)psVar2[4] ^ 0x80000000) -
                                              DOUBLE_803e7270) * dVar4) * dVar3 +
              (double)(*(float *)(iVar1 + 0x10) +
                      (float)((double)CONCAT44(0x43300000,(int)psVar2[5] ^ 0x80000000) -
                             DOUBLE_803e7270)));
  dVar3 = (double)FUN_80293eac();
  *(float *)(param_1 + 10) =
       (float)((double)(float)((double)CONCAT44(0x43300000,(int)psVar2[4] ^ 0x80000000) -
                              DOUBLE_803e7270) * dVar3 + (double)*(float *)(iVar1 + 0x14));
  return;
}

