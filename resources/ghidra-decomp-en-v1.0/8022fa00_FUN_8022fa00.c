// Function: FUN_8022fa00
// Entry: 8022fa00
// Size: 348 bytes

void FUN_8022fa00(int param_1,int param_2)

{
  char cVar1;
  float fVar2;
  float fVar3;
  
  cVar1 = *(char *)(param_2 + 1);
  if ((cVar1 == '\x01') || (cVar1 == '\x03')) {
    *(float *)(param_1 + 0xc) = *(float *)(param_2 + 4) * FLOAT_803db414 + *(float *)(param_1 + 0xc)
    ;
    fVar2 = *(float *)(param_1 + 0xc);
    fVar3 = *(float *)(param_2 + 8) +
            (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 2)) - DOUBLE_803e7098);
    if (fVar2 <= fVar3) {
      fVar3 = *(float *)(param_2 + 8) -
              (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 2)) - DOUBLE_803e7098)
      ;
      if (fVar2 < fVar3) {
        *(float *)(param_1 + 0xc) = fVar3 - (fVar2 - fVar3);
        *(float *)(param_2 + 4) = -*(float *)(param_2 + 4);
      }
    }
    else {
      *(float *)(param_1 + 0xc) = fVar3 - (fVar2 - fVar3);
      *(float *)(param_2 + 4) = -*(float *)(param_2 + 4);
    }
  }
  else if ((cVar1 == '\x04') || (cVar1 == '\x05')) {
    *(float *)(param_1 + 0x10) =
         *(float *)(param_2 + 4) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    fVar2 = *(float *)(param_1 + 0x10);
    fVar3 = *(float *)(param_2 + 0xc) +
            (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 2)) - DOUBLE_803e7098);
    if (fVar2 <= fVar3) {
      fVar3 = *(float *)(param_2 + 0xc) -
              (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 2)) - DOUBLE_803e7098)
      ;
      if (fVar2 < fVar3) {
        *(float *)(param_1 + 0x10) = fVar3 - (fVar2 - fVar3);
        *(float *)(param_2 + 4) = -*(float *)(param_2 + 4);
      }
    }
    else {
      *(float *)(param_1 + 0x10) = fVar3 - (fVar2 - fVar3);
      *(float *)(param_2 + 4) = -*(float *)(param_2 + 4);
    }
  }
  return;
}

