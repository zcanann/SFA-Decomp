// Function: FUN_801aff98
// Entry: 801aff98
// Size: 416 bytes

/* WARNING: Removing unreachable block (ram,0x801b0114) */
/* WARNING: Removing unreachable block (ram,0x801affa8) */

void FUN_801aff98(undefined2 *param_1,uint param_2,uint param_3)

{
  undefined4 uVar1;
  int *piVar2;
  double dVar3;
  double dVar4;
  
  piVar2 = *(int **)(param_1 + 0x5c);
  dVar4 = (double)(FLOAT_803e5470 *
                  (float)((double)CONCAT44(0x43300000,param_3 ^ 0x80000000) - DOUBLE_803e5480));
  uVar1 = *(undefined4 *)(*piVar2 + 0xc);
  *(undefined4 *)(param_1 + 0xc) = uVar1;
  *(undefined4 *)(param_1 + 6) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x10);
  *(undefined4 *)(param_1 + 0xe) = uVar1;
  *(undefined4 *)(param_1 + 8) = uVar1;
  uVar1 = *(undefined4 *)(*piVar2 + 0x14);
  *(undefined4 *)(param_1 + 0x10) = uVar1;
  *(undefined4 *)(param_1 + 10) = uVar1;
  *(undefined4 *)(param_1 + 0x46) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x40) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(param_1 + 0x48) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x42) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(param_1 + 0x4a) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(param_1 + 0x44) = *(undefined4 *)(param_1 + 10);
  *param_1 = (short)((int)*(char *)(*(int *)(param_1 + 0x26) + 0x18) << 8);
  dVar3 = (double)FUN_802945e0();
  *(float *)(param_1 + 0x12) = (float)(dVar4 * -dVar3);
  *(float *)(param_1 + 0x14) =
       FLOAT_803e5470 * (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e5480)
  ;
  dVar3 = (double)FUN_80294964();
  *(float *)(param_1 + 0x16) = (float)(dVar4 * -dVar3);
  param_1[3] = param_1[3] & 0xbfff;
  FUN_80036018((int)param_1);
  *(byte *)(piVar2 + 4) = *(byte *)(piVar2 + 4) & 0xef;
  return;
}

