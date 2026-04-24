// Function: FUN_80183250
// Entry: 80183250
// Size: 404 bytes

void FUN_80183250(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_8002b9ec();
  if ((*(ushort *)(*(int *)(param_1 + 0x30) + 0xb0) & 0x1000) == 0) {
    fVar1 = *(float *)(param_1 + 0x24);
    *(float *)(param_1 + 0x24) =
         -(float)((double)CONCAT44(0x43300000,
                                   (int)*(short *)(*(int *)(param_1 + 0x30) + 4) +
                                   (uint)*(ushort *)(param_2 + 0x20) ^ 0x80000000) - DOUBLE_803e39c8
                 ) / *(float *)(param_2 + 0x1c);
    if (((((fVar1 <= FLOAT_803e39b8) && (FLOAT_803e39b8 <= *(float *)(param_1 + 0x24))) ||
         ((FLOAT_803e39b8 <= fVar1 && (*(float *)(param_1 + 0x24) <= FLOAT_803e39b8)))) &&
        ((((iVar3 = *(int *)(iVar3 + 0x14), iVar3 == 0x465d7 || (iVar3 - 0x465d5U < 2)) ||
          (iVar3 == 0x66)) || ((iVar3 == 0x465d0 || (iVar3 == 0x465d2)))))) &&
       ((dVar4 = (double)FUN_80021704(iVar2 + 0x18,param_1 + 0x18), dVar4 < (double)FLOAT_803e39bc
        && (iVar2 = FUN_8001ffb4(0xa71), iVar2 == 0)))) {
      FUN_8000bb18(param_1,0x313);
    }
    *(float *)(param_1 + 0xc) = *(float *)(param_1 + 0xc) + *(float *)(param_1 + 0x24);
    fVar1 = FLOAT_803e39c0 + *(float *)(param_2 + 0x24);
    if (*(float *)(param_1 + 0xc) <= fVar1) {
      fVar1 = *(float *)(param_2 + 0x24) - FLOAT_803e39c4;
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
    *(float *)(param_1 + 0x24) = FLOAT_803e39b8;
  }
  return;
}

