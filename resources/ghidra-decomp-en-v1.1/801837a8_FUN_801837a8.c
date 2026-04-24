// Function: FUN_801837a8
// Entry: 801837a8
// Size: 404 bytes

void FUN_801837a8(uint param_1,int param_2)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  double dVar5;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8002bac4();
  if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
    fVar1 = *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 0x24) =
         -(float)((double)CONCAT44(0x43300000,
                                   (int)*(short *)(*(int *)(param_1 + 0x30) + 4) +
                                   (uint)*(ushort *)(param_2 + 0x20) ^ 0x80000000) - DOUBLE_803e4660
                 ) / *(float *)(param_2 + 0x1c);
    if (((((fVar1 <= FLOAT_803e4650) && (FLOAT_803e4650 <= *(float *)(param_1 + 0x24))) ||
         ((FLOAT_803e4650 <= fVar1 && (*(float *)(param_1 + 0x24) <= FLOAT_803e4650)))) &&
        ((((iVar4 = *(int *)(iVar4 + 0x14), iVar4 == 0x465d7 || (iVar4 - 0x465d5U < 2)) ||
          (iVar4 == 0x66)) || ((iVar4 == 0x465d0 || (iVar4 == 0x465d2)))))) &&
       ((dVar5 = (double)FUN_800217c8((float *)(iVar2 + 0x18),(float *)(param_1 + 0x18)),
        dVar5 < (double)FLOAT_803e4654 && (uVar3 = FUN_80020078(0xa71), uVar3 == 0)))) {
      FUN_8000bb38(param_1,0x313);
    }
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + *(float *)(param_1 + 0x24);
    fVar1 = FLOAT_803e4658 + *(float *)(param_2 + 0x24);
    if (*(float *)(param_1 + 0xc) <= fVar1) {
      fVar1 = *(float *)(param_2 + 0x24) - FLOAT_803e465c;
      if (*(float *)(param_1 + 0xc) < fVar1) {
        *(float *)(param_1 + 0xc) = fVar1;
      }
    }
    else {
      *(float *)(param_1 + 0xc) = fVar1;
    }
  }
  else {
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_2 + 0x24);
    *(float *)(param_1 + 0x24) = FLOAT_803e4650;
  }
  return;
}

