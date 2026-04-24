// Function: FUN_80208b40
// Entry: 80208b40
// Size: 344 bytes

/* WARNING: Removing unreachable block (ram,0x80208c70) */
/* WARNING: Removing unreachable block (ram,0x80208c68) */
/* WARNING: Removing unreachable block (ram,0x80208b58) */
/* WARNING: Removing unreachable block (ram,0x80208b50) */

void FUN_80208b40(int *param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  float local_90;
  float local_8c;
  float local_88;
  int aiStack_84 [21];
  
  iVar3 = 0;
  iVar4 = param_2;
  while( true ) {
    if (*(char *)(param_2 + 0x68) <= iVar3) {
      return;
    }
    local_90 = *(float *)(iVar4 + 4) + (float)param_1[3];
    dVar5 = (double)local_90;
    local_8c = *(float *)(iVar4 + 8) + (float)param_1[4];
    local_88 = *(float *)(iVar4 + 0xc) + (float)param_1[5];
    dVar6 = (double)local_88;
    iVar2 = FUN_80064248(param_1 + 3,&local_90,(float *)0x1,aiStack_84,param_1,8,0xffffffff,0,0);
    if (iVar2 != 0) break;
    iVar4 = iVar4 + 0xc;
    iVar3 = iVar3 + 1;
  }
  if (FLOAT_803e7124 != (float)param_1[9]) {
    param_1[3] = (int)((float)param_1[3] + (float)((double)local_90 - dVar5));
  }
  if (FLOAT_803e7124 != (float)param_1[0xb]) {
    param_1[5] = (int)((float)param_1[5] + (float)((double)local_88 - dVar6));
  }
  fVar1 = FLOAT_803e7124;
  param_1[9] = (int)FLOAT_803e7124;
  param_1[10] = (int)fVar1;
  param_1[0xb] = (int)fVar1;
  FUN_8000bb38((uint)param_1,0x1d0);
  return;
}

