// Function: FUN_8014c540
// Entry: 8014c540
// Size: 128 bytes

void FUN_8014c540(int param_1,uint *param_2,float *param_3,float *param_4)

{
  float fVar1;
  double dVar2;
  int iVar3;
  
  dVar2 = DOUBLE_803e25e0;
  fVar1 = FLOAT_803e2574;
  if ((param_1 == 0) || (iVar3 = *(int *)(param_1 + 0xb8), iVar3 == 0)) {
    *param_3 = FLOAT_803e2574;
    *param_4 = fVar1;
    *param_2 = 0;
  }
  else {
    *param_3 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x2f3)) - DOUBLE_803e25e0
                      ) / FLOAT_803e257c;
    *param_4 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x2f4)) - dVar2);
    *param_2 = (uint)*(byte *)(iVar3 + 0x2f2);
  }
  return;
}

