// Function: FUN_8015f018
// Entry: 8015f018
// Size: 432 bytes

void FUN_8015f018(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  float *pfVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_80286840();
  uVar5 = (uint)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  pfVar7 = *(float **)(iVar6 + 0x40c);
  iVar4 = (**(code **)(*DAT_803dd738 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar6 + 0x3fe)) -
                                    DOUBLE_803e3a58),uVar5,param_3,0x8000);
  if ((iVar4 == 0) || ((*(byte *)(iVar6 + 0x404) & 4) != 0)) {
    iVar4 = FUN_8002bac4();
    if (iVar4 == 0) {
      dVar8 = (double)FLOAT_803e3a84;
    }
    else {
      fVar1 = *(float *)(iVar4 + 0x18) - *(float *)(uVar5 + 0x18);
      fVar2 = *(float *)(iVar4 + 0x1c) - *(float *)(uVar5 + 0x1c);
      fVar3 = *(float *)(iVar4 + 0x20) - *(float *)(uVar5 + 0x20);
      dVar8 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    }
    if ((pfVar7[1] < *pfVar7) && (dVar8 < (double)FLOAT_803e3a98)) {
      FUN_8000bb38(uVar5,0x265);
      uVar5 = FUN_80022264(0x32,0xfa);
      pfVar7[1] = pfVar7[1] +
                  (float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000) - DOUBLE_803e3aa0);
    }
    *pfVar7 = *pfVar7 + FLOAT_803dc074;
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x28))
              (uVar5,param_3,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar4;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(iVar6 + 0x402) = 1;
  }
  FUN_8028688c();
  return;
}

