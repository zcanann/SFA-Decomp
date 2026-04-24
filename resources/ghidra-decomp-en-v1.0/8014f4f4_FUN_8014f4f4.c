// Function: FUN_8014f4f4
// Entry: 8014f4f4
// Size: 292 bytes

void FUN_8014f4f4(int param_1,int param_2,int param_3)

{
  double dVar1;
  int iVar2;
  char cVar3;
  int *piVar4;
  
  dVar1 = DOUBLE_803e26a8;
  piVar4 = *(int **)(param_1 + 0xb8);
  piVar4[2] = (int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000
                                            ) - DOUBLE_803e26a8) / FLOAT_803e26cc);
  piVar4[5] = (int)(FLOAT_803e2698 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar1));
  piVar4[6] = (int)FLOAT_803e26b4;
  if (param_3 == 0) {
    iVar2 = FUN_80023cc8(0x108,0x1a,0);
    *piVar4 = iVar2;
    if (*piVar4 != 0) {
      FUN_800033a8(*piVar4,0,0x108);
    }
    cVar3 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)(float)piVar4[5],*piVar4,param_1,&DAT_803dbc78,0xffffffff);
    if (cVar3 == '\0') {
      *(byte *)(piVar4 + 7) = *(byte *)(piVar4 + 7) | 1;
    }
    FUN_8000bb18(param_1,0x23a);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

