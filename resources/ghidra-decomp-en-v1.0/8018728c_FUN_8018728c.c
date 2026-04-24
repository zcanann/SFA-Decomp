// Function: FUN_8018728c
// Entry: 8018728c
// Size: 316 bytes

/* WARNING: Removing unreachable block (ram,0x801873a0) */

undefined4 FUN_8018728c(int param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  undefined4 uVar4;
  undefined8 in_f31;
  double dVar5;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar3 = *(int **)(param_1 + 0xb8);
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar1 = iVar1 + 1) {
    if ((*(char *)(param_3 + iVar1 + 0x81) == '\x01') && (*(byte *)(piVar3 + 7) != 0)) {
      if (piVar3[*(byte *)(piVar3 + 7) - 1] != 0) {
        (**(code **)(**(int **)(piVar3[*(byte *)(piVar3 + 7) - 1] + 0x68) + 0x24))();
      }
      *(char *)(piVar3 + 7) = *(char *)(piVar3 + 7) + -1;
      *(char *)((int)piVar3 + 0x1d) = *(char *)((int)piVar3 + 0x1d) + -1;
      FUN_800200e8((int)*(short *)(piVar3 + 8),*(undefined *)((int)piVar3 + 0x1d));
    }
  }
  *(byte *)((int)piVar3 + 0x1e) = *(byte *)((int)piVar3 + 0x1e) & 0x7f | 0x80;
  dVar5 = (double)FLOAT_803e3aec;
  piVar2 = piVar3;
  for (iVar1 = 0; iVar1 < (int)(uint)*(byte *)(piVar3 + 7); iVar1 = iVar1 + 1) {
    (**(code **)(**(int **)(*piVar2 + 0x68) + 0x28))
              ((double)*(float *)(param_1 + 0xc),
               (double)(float)(dVar5 + (double)*(float *)(param_1 + 0x10)),
               (double)*(float *)(param_1 + 0x14));
    piVar2 = piVar2 + 1;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return 0;
}

