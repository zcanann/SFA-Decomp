// Function: FUN_801d0c74
// Entry: 801d0c74
// Size: 284 bytes

/* WARNING: Removing unreachable block (ram,0x801d0cb8) */

void FUN_801d0c74(int param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar2 = FUN_8002ba84();
  if (iVar2 != 0) {
    bVar1 = *pbVar4;
    if (bVar1 == 2) {
      iVar2 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x38))(iVar2,param_1);
      if (iVar2 != 0) {
        *pbVar4 = 3;
      }
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        uVar3 = FUN_80020078(0x94);
        if (uVar3 != 0) {
          FUN_800201ac(0x4e4,0);
          FUN_800201ac(0x4e5,0);
          FUN_800201ac(0xc11,1);
          *pbVar4 = 1;
        }
      }
      else {
        *pbVar4 = 2;
      }
    }
    else if (((bVar1 != 4) && (bVar1 < 4)) && (uVar3 = FUN_80020078(0xbf), uVar3 != 0)) {
      FUN_800201ac(0x4e4,1);
      FUN_800201ac(0x4e5,1);
      FUN_800201ac(0xc11,0);
    }
  }
  return;
}

