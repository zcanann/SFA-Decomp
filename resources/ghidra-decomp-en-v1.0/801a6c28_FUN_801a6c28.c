// Function: FUN_801a6c28
// Entry: 801a6c28
// Size: 308 bytes

void FUN_801a6c28(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  byte *pbVar6;
  
  iVar2 = FUN_802860d8();
  pbVar6 = *(byte **)(iVar2 + 0xb8);
  iVar5 = *(int *)(iVar2 + 0x4c);
  if ((*pbVar6 == 0) && (iVar3 = FUN_8001ffb4((int)*(short *)(iVar5 + 0x18)), iVar3 != 0)) {
    *pbVar6 = 2;
  }
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
    bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
    if (bVar1 == 2) {
      (**(code **)(*DAT_803dca88 + 8))(iVar2,0x70b,0,2,0xffffffff,0);
      iVar4 = 0;
      do {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x70c,0,2,0xffffffff,0);
        iVar4 = iVar4 + 1;
      } while (iVar4 < 0x28);
    }
    else if ((bVar1 < 2) && (bVar1 != 0)) {
      *pbVar6 = 1;
      iVar4 = (int)*(short *)(iVar5 + 0x1a);
      if (iVar4 != -1) {
        FUN_800200e8(iVar4,1);
      }
    }
  }
  FUN_80286124((2 - *pbVar6 | *pbVar6 - 2) >> 0x1f);
  return;
}

