// Function: FUN_801877e4
// Entry: 801877e4
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801878f8) */
/* WARNING: Removing unreachable block (ram,0x801877f4) */

undefined4 FUN_801877e4(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  double dVar4;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if ((*(char *)(param_3 + iVar1 + 0x81) == '\x01') && (*(byte *)(piVar3 + 7) != 0)) {
      if (piVar3[*(byte *)(piVar3 + 7) - 1] != 0) {
        (**(code **)(**(int **)(piVar3[*(byte *)(piVar3 + 7) - 1] + 0x68) + 0x24))();
      }
      *(char *)(piVar3 + 7) = *(char *)(piVar3 + 7) + -1;
      *(char *)((int)piVar3 + 0x1d) = *(char *)((int)piVar3 + 0x1d) + -1;
      FUN_800201ac((int)*(short *)(piVar3 + 8),(uint)*(byte *)((int)piVar3 + 0x1d));
    }
  }
  *(byte *)((int)piVar3 + 0x1e) = *(byte *)((int)piVar3 + 0x1e) & 0x7f | 0x80;
  dVar4 = (double)FLOAT_803e4784;
  piVar2 = piVar3;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(piVar3 + 7); iVar1 = iVar1 + 1) {
    (**(code **)(**(int **)(*piVar2 + 0x68) + 0x28))
              ((double)*(float *)(param_1 + 0xc),
               (double)(float)(dVar4 + (double)*(float *)(param_1 + 0x10)),
               (double)*(float *)(param_1 + 0x14));
    piVar2 = piVar2 + 1;
  }
  return 0;
}

