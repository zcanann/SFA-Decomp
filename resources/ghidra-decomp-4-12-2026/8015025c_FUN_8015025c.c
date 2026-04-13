// Function: FUN_8015025c
// Entry: 8015025c
// Size: 296 bytes

void FUN_8015025c(uint param_1,int param_2,int param_3)

{
  float fVar1;
  double dVar2;
  int iVar3;
  char cVar4;
  int *piVar5;
  
  dVar2 = DOUBLE_803e3398;
  piVar5 = *(int **)(param_1 + 0xb8);
  fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x1a) ^ 0x80000000) -
                 DOUBLE_803e3398) / FLOAT_803e33b4;
  piVar5[3] = (int)fVar1;
  piVar5[2] = (int)fVar1;
  piVar5[6] = (int)(FLOAT_803e33b8 *
                   (float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x19) ^ 0x80000000)
                          - dVar2));
  piVar5[8] = 0x337;
  if (param_3 == 0) {
    iVar3 = FUN_80023d8c(0x108,0x1a);
    *piVar5 = iVar3;
    if (*piVar5 != 0) {
      FUN_800033a8(*piVar5,0,0x108);
    }
    cVar4 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)(float)piVar5[6],*piVar5,param_1,&DAT_803dc8e8,0xffffffff);
    if (cVar4 == '\0') {
      *(byte *)(piVar5 + 9) = *(byte *)(piVar5 + 9) | 1;
    }
    FUN_8000bb38(param_1,0x23b);
  }
  *(ushort *)(param_1 + 0xb0) = *(ushort *)(param_1 + 0xb0) | 0x2000;
  return;
}

