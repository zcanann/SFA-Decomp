// Function: FUN_80160ce8
// Entry: 80160ce8
// Size: 384 bytes

void FUN_80160ce8(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  
  if (*(int *)(param_1 + 200) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 200) + 0x30) = *(undefined4 *)(param_1 + 0x30);
  }
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  FUN_8003b408(param_1,param_2 + 0x3ac);
  if ((*(byte *)(param_2 + 0x404) & 1) == 0) {
    (**(code **)(*DAT_803dd738 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fc),
               (int)*(short *)(param_2 + 0x3fa));
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),param_2 + 0x405,0,0,0)
  ;
  iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                    (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),&DAT_80320c58,
                     &DAT_80320cd0,1,0);
  if (3 < iVar4) {
    *(undefined *)(param_2 + 0x405) = 2;
    uVar5 = FUN_8002bac4();
    *(undefined4 *)(param_3 + 0x2d0) = uVar5;
  }
  return;
}

