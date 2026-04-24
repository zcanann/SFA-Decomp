// Function: FUN_8015d3c0
// Entry: 8015d3c0
// Size: 504 bytes

void FUN_8015d3c0(int param_1,int param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  float *pfVar5;
  double dVar6;
  undefined auStack44 [28];
  
  pfVar5 = *(float **)(param_2 + 0x40c);
  FUN_8002b9ec();
  iVar4 = *(int *)(param_3 + 0x2d0);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(param_1 + 0x18);
    fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(param_1 + 0x1c);
    fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(param_1 + 0x20);
    dVar6 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    *(float *)(param_3 + 0x2c0) = (float)dVar6;
  }
  if ((*(byte *)(param_2 + 0x404) & 0x20) == 0) {
    (**(code **)(*DAT_803dcab8 + 0x3c))
              (param_1,param_3,param_2 + 0x400,2,3,(int)*(short *)(param_2 + 0x3fc),
               (int)*(short *)(param_2 + 0x3fa));
  }
  (**(code **)(*DAT_803dcab8 + 0x54))
            (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8);
  *pfVar5 = *pfVar5 + FLOAT_803db414;
  if ((*(short *)(param_3 + 0x274) != 3) &&
     (iVar4 = (**(code **)(*DAT_803dcab8 + 0x50))
                        (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),
                         &DAT_8031fda0,&DAT_8031fe18,1,auStack44), iVar4 != 0)) {
    if (FLOAT_803e2db4 <= *pfVar5) {
      *(undefined2 *)((int)pfVar5 + 6) = 0;
    }
    else {
      *(short *)((int)pfVar5 + 6) = *(short *)((int)pfVar5 + 6) + 1;
    }
    *pfVar5 = FLOAT_803e2d14;
    if (('\0' < *(char *)(param_3 + 0x354)) && (1 < *(short *)((int)pfVar5 + 6))) {
      (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,3);
      *(undefined2 *)((int)pfVar5 + 6) = 0;
      *(undefined2 *)(param_3 + 0x270) = 5;
    }
  }
  return;
}

