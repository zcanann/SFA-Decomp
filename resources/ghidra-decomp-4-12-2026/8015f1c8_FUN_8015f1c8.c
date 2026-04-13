// Function: FUN_8015f1c8
// Entry: 8015f1c8
// Size: 380 bytes

void FUN_8015f1c8(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  
  iVar4 = FUN_8002bac4();
  iVar5 = *(int *)(param_3 + 0x2d0);
  if (iVar5 != 0) {
    fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar5 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  if ((*(byte *)(param_2 + 0x404) & 0x20) == 0) {
    (**(code **)(*DAT_803dd738 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fa),
               (int)*(short *)(param_2 + 0x3fc));
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8);
  iVar5 = (**(code **)(*DAT_803dd738 + 0x50))
                    (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),&DAT_80320af8,
                     &DAT_80320b70,1,&DAT_803ad1e0);
  if (iVar5 != 0) {
    (**(code **)(**(int **)(*(int *)(iVar4 + 200) + 0x68) + 0x50))();
  }
  return;
}

