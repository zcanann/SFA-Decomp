// Function: FUN_800614d8
// Entry: 800614d8
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x800617b0) */
/* WARNING: Removing unreachable block (ram,0x800614e8) */

void FUN_800614d8(undefined2 *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  double dVar4;
  float local_a8;
  float afStack_a4 [3];
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  
  iVar3 = FUN_800658e4((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0x10),
                       (double)*(float *)(param_2 + 0x14),param_2,&local_a8,afStack_a4,0);
  if (iVar3 == 0) {
    FUN_80247ef8(afStack_a4,afStack_a4);
    local_8c = FLOAT_803df8e8;
    local_88 = FLOAT_803df8d8;
    local_84 = FLOAT_803df8d8;
    dVar4 = FUN_80247f90(afStack_a4,&local_8c);
    if ((double)FLOAT_803df8ec <= ABS(dVar4)) {
      local_8c = FLOAT_803df8d8;
      local_84 = FLOAT_803df8e8;
    }
    FUN_80247fb0(afStack_a4,&local_8c,&local_98);
    FUN_80247fb0(&local_98,afStack_a4,&local_8c);
    FUN_80247ef8(&local_8c,&local_8c);
    FUN_80247ef8(&local_98,&local_98);
    dVar4 = (double)(FLOAT_803df8f0 * **(float **)(param_2 + 100));
    FUN_80247edc(dVar4,&local_8c,&local_8c);
    FUN_80247edc(dVar4,&local_98,&local_98);
    fVar2 = FLOAT_803df8f4;
    fVar1 = FLOAT_803df8d8;
    local_a8 = -local_a8;
    *param_1 = (short)(int)(FLOAT_803df8f4 * ((FLOAT_803df8d8 - local_8c) - local_98));
    param_1[1] = (short)(int)(fVar2 * ((local_a8 - local_88) - local_94));
    param_1[2] = (short)(int)(fVar2 * ((fVar1 - local_84) - local_90));
    param_1[3] = (short)(int)(fVar2 * ((fVar1 + local_8c) - local_98));
    param_1[4] = (short)(int)(fVar2 * ((local_a8 + local_88) - local_94));
    param_1[5] = (short)(int)(fVar2 * ((fVar1 + local_84) - local_90));
    param_1[6] = (short)(int)(fVar2 * (local_98 + fVar1 + local_8c));
    param_1[7] = (short)(int)(fVar2 * (local_94 + local_a8 + local_88));
    param_1[8] = (short)(int)(fVar2 * (local_90 + fVar1 + local_84));
    param_1[9] = (short)(int)(fVar2 * (local_98 + (fVar1 - local_8c)));
    param_1[10] = (short)(int)(fVar2 * (local_94 + (local_a8 - local_88)));
    param_1[0xb] = (short)(int)(fVar2 * (local_90 + (fVar1 - local_84)));
    *(undefined *)(param_1 + 0xc) = 1;
  }
  else {
    *(undefined *)(param_1 + 0xc) = 0xff;
  }
  return;
}

