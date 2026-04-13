// Function: FUN_8016d1f4
// Entry: 8016d1f4
// Size: 288 bytes

/* WARNING: Removing unreachable block (ram,0x8016d264) */

undefined4 FUN_8016d1f4(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0xb8);
  if ((char)*pbVar3 < '\0') {
    FUN_800551f8((double)*(float *)(param_1 + 0x18),(double)*(float *)(param_1 + 0x1c),
                 (double)*(float *)(param_1 + 0x20),pbVar3[1],pbVar3[2]);
  }
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
    if (bVar1 == 2) {
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      pbVar3[1] = 1;
      pbVar3[2] = 0;
    }
    else if (bVar1 < 2) {
      if (bVar1 == 0) {
        *pbVar3 = *pbVar3 & 0x7f;
        FUN_800551ec();
      }
      else {
        *pbVar3 = *pbVar3 & 0x7f | 0x80;
        pbVar3[1] = 0;
      }
    }
    else if (bVar1 < 4) {
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      pbVar3[2] = 1;
      pbVar3[1] = 0;
    }
  }
  return 0;
}

