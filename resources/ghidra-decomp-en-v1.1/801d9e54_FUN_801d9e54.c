// Function: FUN_801d9e54
// Entry: 801d9e54
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x801d9ee4) */

void FUN_801d9e54(int param_1)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  byte *pbVar6;
  short local_18 [8];
  
  pbVar6 = *(byte **)(param_1 + 0xb8);
  bVar2 = false;
  iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if ((0 < iVar3) && (iVar5 = 0, 0 < iVar3)) {
    do {
      if (*(short *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x44) == 1) {
        bVar2 = true;
      }
      iVar5 = iVar5 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (bVar2) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    bVar1 = *pbVar6;
    if (bVar1 == 2) {
      iVar3 = FUN_8003811c(param_1);
      if (iVar3 != 0) {
        FUN_800201ac(0x886,1);
      }
    }
    else if (bVar1 < 2) {
      FUN_8011f68c(local_18);
      uVar4 = FUN_80020078(0xc7c);
      if (((uVar4 == 0) || (iVar3 = FUN_8012f000(), iVar3 == -1)) && (local_18[0] != 0xc7c)) {
        FUN_8002b7b0(param_1,0,0,0,'\0','\x02');
      }
      else {
        FUN_8002b7b0(param_1,0,0,0,'\0','\x04');
      }
      iVar3 = FUN_8003809c(param_1,0xc7c);
      if (iVar3 == 0) {
        iVar3 = FUN_8003811c(param_1);
        if (iVar3 != 0) {
          FUN_800201ac(0xc7e,1);
        }
      }
      else {
        FUN_800201ac(0x886,1);
        FUN_800201ac(0xc7d,1);
        *pbVar6 = 2;
        FUN_8002b7b0(param_1,0,0,0,'\0','\x03');
      }
    }
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  }
  return;
}

