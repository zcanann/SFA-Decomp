// Function: FUN_8014f988
// Entry: 8014f988
// Size: 292 bytes

void FUN_8014f988(uint param_1,int param_2,int param_3)

{
  double dVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  
  dVar1 = DOUBLE_803e3340;
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e3340) / FLOAT_803e3364);
  piVar4[5] = (int)(FLOAT_803e3330 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  piVar4[6] = (int)FLOAT_803e334c;
  if (param_3 == 0) {
    iVar2 = FUN_80023d8c(0x108,0x1a);
    *piVar4 = iVar2;
    if (*piVar4 != 0) {
      FUN_800033a8(*piVar4,0,0x108);
    }
    cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar4[5],*piVar4,param_1,&DAT_803dc8e0,0xffffffff);
    if (cVar3 == '\0') {
      *(byte *)(piVar4 + 7) = *(byte *)(piVar4 + 7) | 1;
    }
    FUN_8000bb38(param_1,0x23a);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

