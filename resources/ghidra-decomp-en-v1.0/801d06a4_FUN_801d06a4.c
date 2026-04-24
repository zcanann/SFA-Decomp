// Function: FUN_801d06a4
// Entry: 801d06a4
// Size: 284 bytes

/* WARNING: Removing unreachable block (ram,0x801d06e8) */

void FUN_801d06a4(int param_1)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_8002b9ac();
  if (iVar2 != 0) {
    bVar1 = *pbVar3;
    if (bVar1 == 2) {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      if (iVar2 != 0) {
        *pbVar3 = 3;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = FUN_8001ffb4(0x94);
        if (iVar2 != 0) {
          FUN_800200e8(0x4e4,0);
          FUN_800200e8(0x4e5,0);
          FUN_800200e8(0xc11,1);
          *pbVar3 = 1;
        }
      }
      else {
        *pbVar3 = 2;
      }
    }
    else if (((bVar1 != 4) && (bVar1 < 4)) && (iVar2 = FUN_8001ffb4(0xbf), iVar2 != 0)) {
      FUN_800200e8(0x4e4,1);
      FUN_800200e8(0x4e5,1);
      FUN_800200e8(0xc11,0);
    }
  }
  return;
}

