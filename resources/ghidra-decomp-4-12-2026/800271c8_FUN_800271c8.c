// Function: FUN_800271c8
// Entry: 800271c8
// Size: 184 bytes

void FUN_800271c8(int *param_1,float *param_2)

{
  int iVar1;
  float *pfVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  
  iVar5 = *param_1;
  for (uVar4 = 0; uVar4 < *(byte *)(iVar5 + 0xf3); uVar4 = uVar4 + 1) {
    uVar3 = (uint)*(byte *)(*param_1 + 0xf3);
    if (uVar3 == 0) {
      iVar1 = 1;
    }
    else {
      iVar1 = uVar3 + *(byte *)(*param_1 + 0xf4);
    }
    uVar3 = uVar4;
    if (iVar1 <= (int)uVar4) {
      uVar3 = 0;
    }
    pfVar2 = (float *)(param_1[(*(ushort *)(param_1 + 6) & 1) + 3] + uVar3 * 0x40);
    FUN_80247618(param_2,pfVar2,pfVar2);
  }
  return;
}

