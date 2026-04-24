// Function: FUN_801992ec
// Entry: 801992ec
// Size: 196 bytes

void FUN_801992ec(int param_1,undefined4 param_2)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  int iVar6;
  
  iVar6 = *(int *)(param_1 + 0xb8);
  fVar1 = *(float *)(iVar6 + 0x1c) - *(float *)(param_1 + 0x18);
  fVar2 = *(float *)(iVar6 + 0x20) - *(float *)(param_1 + 0x1c);
  fVar3 = *(float *)(iVar6 + 0x24) - *(float *)(param_1 + 0x20);
  fVar4 = fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2;
  fVar1 = *(float *)(iVar6 + 0x28) - *(float *)(param_1 + 0x18);
  fVar2 = *(float *)(iVar6 + 0x2c) - *(float *)(param_1 + 0x1c);
  fVar3 = *(float *)(iVar6 + 0x30) - *(float *)(param_1 + 0x20);
  fVar2 = fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2;
  fVar1 = *(float *)(iVar6 + 4);
  if (fVar1 <= fVar2) {
    if (fVar1 <= fVar4) {
      cVar5 = -2;
    }
    else {
      cVar5 = -1;
    }
  }
  else if (fVar1 <= fVar4) {
    cVar5 = '\x01';
  }
  else {
    cVar5 = '\x02';
  }
  FUN_801993b0(param_1,param_2,(int)cVar5,(int)fVar2);
  return;
}

