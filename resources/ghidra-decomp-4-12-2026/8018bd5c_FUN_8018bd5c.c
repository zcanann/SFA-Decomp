// Function: FUN_8018bd5c
// Entry: 8018bd5c
// Size: 432 bytes

void FUN_8018bd5c(int param_1)

{
  int iVar1;
  char cVar2;
  int iVar3;
  int *piVar4;
  double dVar5;
  
  piVar4 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8002ba84();
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f;
  if ((iVar1 != 0) && (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(), cVar2 != '\0')) {
    dVar5 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar1 + 0x18));
    if (dVar5 < (double)(float)((double)CONCAT44(0x43300000,
                                                 (int)*(short *)(iVar3 + 0x1a) ^ 0x80000000) -
                               DOUBLE_803e4910)) {
      *piVar4 = *piVar4 - (uint)DAT_803dc070;
      *(byte *)(piVar4 + 1) = *(byte *)(piVar4 + 1) & 0x7f | 0x80;
    }
  }
  if (*piVar4 == 0) {
    if (iVar1 != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x3c))(iVar1);
      *piVar4 = (uint)*(byte *)(iVar3 + 0x19) * 0x3c;
    }
  }
  else if ((iVar1 != 0) &&
          (cVar2 = (**(code **)(**(int **)(iVar1 + 0x68) + 0x44))(iVar1), cVar2 == '\0')) {
    if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
      (**(code **)(**(int **)(iVar1 + 0x68) + 0x28))(iVar1,param_1,1,3);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    FUN_80041110();
  }
  FUN_800201ac((int)*(short *)(iVar3 + 0x1e),(uint)(*(byte *)(piVar4 + 1) >> 7));
  return;
}

