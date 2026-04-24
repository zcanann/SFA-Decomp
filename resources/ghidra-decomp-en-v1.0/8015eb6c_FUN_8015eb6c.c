// Function: FUN_8015eb6c
// Entry: 8015eb6c
// Size: 432 bytes

void FUN_8015eb6c(undefined4 param_1,undefined4 param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float *pfVar8;
  double dVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_802860dc();
  iVar4 = (int)((ulonglong)uVar10 >> 0x20);
  iVar7 = (int)uVar10;
  pfVar8 = *(float **)(iVar7 + 0x40c);
  iVar5 = (**(code **)(*DAT_803dcab8 + 0x48))
                    ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar7 + 0x3fe)) -
                                    DOUBLE_803e2dc0),iVar4,param_3,0x8000);
  if ((iVar5 == 0) || ((*(byte *)(iVar7 + 0x404) & 4) != 0)) {
    iVar5 = FUN_8002b9ec();
    if (iVar5 == 0) {
      dVar9 = (double)FLOAT_803e2dec;
    }
    else {
      fVar1 = *(float *)(iVar5 + 0x18) - *(float *)(iVar4 + 0x18);
      fVar2 = *(float *)(iVar5 + 0x1c) - *(float *)(iVar4 + 0x1c);
      fVar3 = *(float *)(iVar5 + 0x20) - *(float *)(iVar4 + 0x20);
      dVar9 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
    }
    if ((pfVar8[1] < *pfVar8) && (dVar9 < (double)FLOAT_803e2e00)) {
      FUN_8000bb18(iVar4,0x265);
      uVar6 = FUN_800221a0(0x32,0xfa);
      pfVar8[1] = pfVar8[1] +
                  (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803e2e08);
    }
    *pfVar8 = *pfVar8 + FLOAT_803db414;
  }
  else {
    (**(code **)(*DAT_803dcab8 + 0x28))
              (iVar4,param_3,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar5;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(iVar7 + 0x402) = 1;
  }
  FUN_80286128();
  return;
}

