// Function: FUN_8018a8bc
// Entry: 8018a8bc
// Size: 248 bytes

void FUN_8018a8bc(undefined4 param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  int iVar5;
  int iVar6;
  
  iVar2 = FUN_802860dc();
  iVar5 = *(int *)(iVar2 + 0x4c);
  pbVar4 = *(byte **)(iVar2 + 0xb8);
  for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar6 = iVar6 + 1) {
    bVar1 = *(byte *)(param_3 + iVar6 + 0x81);
    if (bVar1 == 3) {
      *pbVar4 = *pbVar4 & 0xdf;
    }
    else if (bVar1 < 3) {
      if (bVar1 == 1) {
        iVar3 = (int)*(short *)(iVar5 + 0x1c);
        if (iVar3 != 0) {
          (**(code **)(*DAT_803dca68 + 0x38))(iVar3,200,0x8c,0);
        }
      }
      else if (bVar1 != 0) {
        *pbVar4 = *pbVar4 & 0xdf | 0x20;
      }
    }
    else if (bVar1 < 5) {
      *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      FUN_80035f00(iVar2);
    }
  }
  FUN_80286128(0);
  return;
}

