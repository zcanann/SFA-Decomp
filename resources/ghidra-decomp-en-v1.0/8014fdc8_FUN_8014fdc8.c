// Function: FUN_8014fdc8
// Entry: 8014fdc8
// Size: 296 bytes

void FUN_8014fdc8(int param_1,int param_2,int param_3)

{
  float fVar1;
  double dVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  
  dVar2 = DOUBLE_803e2700;
  piVar5 = *(int **)(param_1 + 0xb8);
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e2700) / FLOAT_803e271c;
  piVar5[3] = (int)fVar1;
  piVar5[2] = (int)fVar1;
  piVar5[6] = (int)(FLOAT_803e2720 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar2));
  piVar5[8] = 0x337;
  if (param_3 == 0) {
    iVar3 = FUN_80023cc8(0x108,0x1a,0);
    *piVar5 = iVar3;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dca9c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dbc80,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)(piVar5 + 9) = *(byte *)(piVar5 + 9) | 1;
    }
    FUN_8000bb18(param_1,0x23b);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

