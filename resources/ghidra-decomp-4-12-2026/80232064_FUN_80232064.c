// Function: FUN_80232064
// Entry: 80232064
// Size: 184 bytes

/* WARNING: Removing unreachable block (ram,0x802320c4) */

void FUN_80232064(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  iVar1 = *(int *)(param_9 + 0x4c);
  dVar4 = (double)*pfVar2;
  dVar3 = (double)FLOAT_803e7dec;
  if ((dVar3 < dVar4) &&
     (*pfVar2 = (float)(dVar4 - (double)FLOAT_803dc074), (double)*pfVar2 <= dVar3)) {
    if (*(char *)(iVar1 + 0x25) == '\x01') {
      FUN_80231cb0(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,pfVar2,iVar1)
      ;
    }
    else if (*(char *)(iVar1 + 0x25) == '\0') {
      FUN_80231e6c(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,pfVar2,iVar1)
      ;
    }
    *pfVar2 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x18)) - DOUBLE_803e7df0
                     );
  }
  return;
}

