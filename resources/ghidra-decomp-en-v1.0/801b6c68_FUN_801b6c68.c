// Function: FUN_801b6c68
// Entry: 801b6c68
// Size: 200 bytes

/* WARNING: Removing unreachable block (ram,0x801b6cac) */

void FUN_801b6c68(int param_1)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_8002b9ac();
  if (iVar2 != 0) {
    bVar1 = *pbVar3;
    if (bVar1 == 2) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      *pbVar3 = 3;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar2 = FUN_8001ffb4(0xa1b);
        if (iVar2 != 0) {
          FUN_800200e8(0x4e4,0);
          FUN_800200e8(0x4e5,0);
          *pbVar3 = 1;
        }
      }
      else {
        *pbVar3 = 2;
      }
    }
  }
  return;
}

