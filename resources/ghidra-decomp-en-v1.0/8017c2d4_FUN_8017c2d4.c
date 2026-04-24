// Function: FUN_8017c2d4
// Entry: 8017c2d4
// Size: 292 bytes

undefined4 FUN_8017c2d4(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  
  if (*(short *)(param_1 + 0xb4) != -1) {
    iVar4 = *(int *)(param_1 + 0x4c);
    pbVar3 = *(byte **)(param_1 + 0xb8);
    *(undefined *)(param_3 + 0x56) = 0;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
      bVar1 = *(byte *)(param_3 + iVar2 + 0x81);
      if (bVar1 == 2) {
        if (*(char *)(iVar4 + 0x24) != '\0') {
          FUN_800552e8(*(char *)(iVar4 + 0x24),0);
        }
      }
      else if (bVar1 < 2) {
        if (((bVar1 != 0) && ((*(byte *)(iVar4 + 0x1d) & 1) == 0)) &&
           ((*(byte *)(iVar4 + 0x1d) & 2) != 0)) {
          FUN_800200e8((int)*(short *)(iVar4 + 0x18),1);
        }
      }
      else if (bVar1 < 4) {
        (**(code **)(*DAT_803dca54 + 0x50))(0x56,1,0,0);
      }
    }
    *pbVar3 = *pbVar3 | 4;
  }
  return 0;
}

