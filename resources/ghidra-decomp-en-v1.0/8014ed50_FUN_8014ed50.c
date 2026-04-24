// Function: FUN_8014ed50
// Entry: 8014ed50
// Size: 308 bytes

void FUN_8014ed50(int param_1,int param_2,int param_3)

{
  double dVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  
  dVar1 = DOUBLE_803e2648;
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e2648) / FLOAT_803e266c);
  piVar4[3] = (int)FLOAT_803e2670;
  piVar4[6] = (int)(FLOAT_803e2674 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  if (param_3 == 0) {
    iVar2 = FUN_80023cc8(0x108,0x1a,0);
    *piVar4 = iVar2;
    if (*piVar4 != 0) {
      FUN_800033a8(*piVar4,0,0x108);
    }
    cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)(float)piVar4[6],*piVar4,param_1,&DAT_803dbc70,0xffffffff);
    if (cVar3 == '\0') {
      *(byte *)((int)piVar4 + 0x26) = *(byte *)((int)piVar4 + 0x26) | 1;
    }
  }
  if ((*(short *)(param_2 + 0x20) != -1) && (iVar2 = FUN_8001ffb4(), iVar2 != 0)) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

