// Function: FUN_80062378
// Entry: 80062378
// Size: 288 bytes

int FUN_80062378(int param_1,uint param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  double dVar5;
  double local_28;
  
  if ((*(byte *)(*(int *)(param_1 + 0x50) + 0x5f) & 4) == 0) {
    uVar4 = 400;
    iVar3 = 500;
  }
  else {
    uVar4 = 1000;
    iVar3 = 2000;
  }
  dVar5 = (double)FUN_8000f480((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c)
                               ,(double)*(float *)(param_1 + 0x20));
  local_28 = (double)CONCAT44(0x43300000,uVar4 ^ 0x80000000);
  fVar1 = (float)(dVar5 - (double)(float)(local_28 - DOUBLE_803dec60)) /
          (float)((double)CONCAT44(0x43300000,iVar3 - uVar4 ^ 0x80000000) - DOUBLE_803dec60);
  fVar2 = FLOAT_803dec58;
  if ((FLOAT_803dec58 <= fVar1) && (fVar2 = fVar1, FLOAT_803dec68 < fVar1)) {
    fVar2 = FLOAT_803dec68;
  }
  return (int)((int)((float)((double)CONCAT44(0x43300000,param_2 & 0xff) - DOUBLE_803dec88) *
                    (FLOAT_803dec68 - fVar2)) * (*(byte *)(param_1 + 0x37) + 1)) >> 8;
}

