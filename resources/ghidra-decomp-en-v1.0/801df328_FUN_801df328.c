// Function: FUN_801df328
// Entry: 801df328
// Size: 276 bytes

/* WARNING: Removing unreachable block (ram,0x801df360) */

void FUN_801df328(int param_1)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  bVar1 = *pbVar3;
  if (bVar1 == 1) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    }
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
  }
  else if (bVar1 == 0) {
    if ((*(short *)(*(int *)(param_1 + 0x4c) + 0x1e) == -1) || (iVar2 = FUN_8001ffb4(), iVar2 == 0))
    {
      *pbVar3 = 1;
    }
    else {
      *pbVar3 = 2;
    }
  }
  else if (bVar1 < 3) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  pbVar3[2] = 0;
  if (((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) && (*(int *)(param_1 + 0x74) != 0)) {
    FUN_80041018(param_1);
  }
  return;
}

