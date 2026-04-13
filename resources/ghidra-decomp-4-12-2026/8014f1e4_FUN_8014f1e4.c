// Function: FUN_8014f1e4
// Entry: 8014f1e4
// Size: 308 bytes

void FUN_8014f1e4(int param_1,int param_2,int param_3)

{
  double dVar1;
  int iVar2;
  char cVar4;
  uint uVar3;
  int *piVar5;
  
  dVar1 = DOUBLE_803e32e0;
  piVar5 = *(int **)(param_1 + 0xb8);
  piVar5[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e32e0) / FLOAT_803e3304);
  piVar5[3] = (int)FLOAT_803e3308;
  piVar5[6] = (int)(FLOAT_803e330c *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  if (param_3 == 0) {
    iVar2 = FUN_80023d8c(0x108,0x1a);
    *piVar5 = iVar2;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dc8d8,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)((int)piVar5 + 0x26) = *(byte *)((int)piVar5 + 0x26) | 1;
    }
  }
  if (((int)*(short *)(param_2 + 0x20) != 0xffffffff) &&
     (uVar3 = FUN_80020078((int)*(short *)(param_2 + 0x20)), uVar3 != 0)) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  return;
}

