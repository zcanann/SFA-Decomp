// Function: FUN_802319a0
// Entry: 802319a0
// Size: 184 bytes

/* WARNING: Removing unreachable block (ram,0x80231a00) */

void FUN_802319a0(int param_1)

{
  float fVar1;
  int iVar2;
  float *pfVar3;
  
  fVar1 = FLOAT_803e7154;
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar2 = *(int *)(param_1 + 0x4c);
  if ((FLOAT_803e7154 < *pfVar3) && (*pfVar3 = *pfVar3 - FLOAT_803db414, *pfVar3 <= fVar1)) {
    if (*(char *)(iVar2 + 0x25) == '\x01') {
      FUN_802315ec(param_1,pfVar3,iVar2);
    }
    else if (*(char *)(iVar2 + 0x25) == '\0') {
      FUN_802317a8(param_1,pfVar3,iVar2);
    }
    *pfVar3 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar2 + 0x18)) - DOUBLE_803e7158
                     );
  }
  return;
}

