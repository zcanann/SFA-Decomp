// Function: FUN_801d9864
// Entry: 801d9864
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x801d98f4) */

void FUN_801d9864(int param_1)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  bool bVar4;
  byte *pbVar5;
  short local_18 [8];
  
  pbVar5 = *(byte **)(param_1 + 0xb8);
  bVar4 = false;
  iVar2 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if ((0 < iVar2) && (iVar3 = 0, 0 < iVar2)) {
    do {
      if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar3 + 0x100) + 0x44) == 1) {
        bVar4 = true;
      }
      iVar3 = iVar3 + 4;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  if (bVar4) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    bVar1 = *pbVar5;
    if (bVar1 == 2) {
      iVar2 = FUN_80038024(param_1);
      if (iVar2 != 0) {
        FUN_800200e8(0x886,1);
      }
    }
    else if (bVar1 < 2) {
      FUN_8011f3a8(local_18);
      iVar2 = FUN_8001ffb4(0xc7c);
      if (((iVar2 == 0) || (iVar2 = FUN_8012ebc8(), iVar2 == -1)) && (local_18[0] != 0xc7c)) {
        FUN_8002b6d8(param_1,0,0,0,0,2);
      }
      else {
        FUN_8002b6d8(param_1,0,0,0,0,4);
      }
      iVar2 = FUN_80037fa4(param_1,0xc7c);
      if (iVar2 == 0) {
        iVar2 = FUN_80038024(param_1);
        if (iVar2 != 0) {
          FUN_800200e8(0xc7e,1);
        }
      }
      else {
        FUN_800200e8(0x886,1);
        FUN_800200e8(0xc7d,1);
        *pbVar5 = 2;
        FUN_8002b6d8(param_1,0,0,0,0,3);
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

