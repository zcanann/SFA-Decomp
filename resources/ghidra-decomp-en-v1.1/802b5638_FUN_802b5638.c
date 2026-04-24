// Function: FUN_802b5638
// Entry: 802b5638
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x802b580c) */
/* WARNING: Removing unreachable block (ram,0x802b5804) */
/* WARNING: Removing unreachable block (ram,0x802b57fc) */
/* WARNING: Removing unreachable block (ram,0x802b5658) */
/* WARNING: Removing unreachable block (ram,0x802b5650) */
/* WARNING: Removing unreachable block (ram,0x802b5648) */

void FUN_802b5638(int param_1,char param_2,char param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double in_f29;
  double in_f30;
  double in_f31;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if ((((param_2 == -1) || ((*(uint *)(iVar5 + 0x360) & 0x4001) == 0)) &&
      ((*(byte *)(iVar5 + 0x3f3) >> 3 & 1) == 0)) && (1 < *(byte *)(param_1 + 0x36))) {
    if ((*(int *)(iVar5 + 0x7f0) != 0) &&
       (((*(ushort *)(param_1 + 0xb0) & 0x1000) != 0 ||
        (iVar4 = FUN_80080100((int *)&DAT_803dd32c,2,(int)*(short *)(iVar5 + 0x274)), iVar4 != -1)))
       ) {
      (**(code **)(**(int **)(*(int *)(iVar5 + 0x7f0) + 0x68) + 0x50))
                ((double)*(float *)(*(int *)(param_1 + 0x50) + 4));
    }
    if ((*(uint *)(iVar5 + 0x360) & 0x8000000) != 0) {
      fVar1 = *(float *)(param_1 + 0xc);
      in_f31 = (double)fVar1;
      fVar2 = *(float *)(param_1 + 0x10);
      in_f30 = (double)fVar2;
      fVar3 = *(float *)(param_1 + 0x14);
      in_f29 = (double)fVar3;
      *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x20);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x24);
      *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(*(int *)(param_1 + 100) + 0x28);
      *(float *)(*(int *)(param_1 + 100) + 0x20) = fVar1;
      *(float *)(*(int *)(param_1 + 100) + 0x24) = fVar2;
      *(float *)(*(int *)(param_1 + 100) + 0x28) = fVar3;
    }
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + *(float *)(iVar5 + 0x7c8);
    if (param_3 == '\x01') {
      FUN_800415ac(param_1);
    }
    else if (param_3 == '\x02') {
      FUN_800414cc(param_1);
    }
    else if (param_3 == '\x04') {
      FUN_800413d4(param_1);
    }
    FUN_800413cc(0);
    *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - *(float *)(iVar5 + 0x7c8);
    if ((*(uint *)(iVar5 + 0x360) & 0x8000000) != 0) {
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x20) = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x24) = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(*(int *)(param_1 + 100) + 0x28) = *(undefined4 *)(param_1 + 0x14);
      *(float *)(param_1 + 0xc) = (float)in_f31;
      *(float *)(param_1 + 0x10) = (float)in_f30;
      *(float *)(param_1 + 0x14) = (float)in_f29;
    }
  }
  return;
}

