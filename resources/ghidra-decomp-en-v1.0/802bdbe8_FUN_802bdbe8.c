// Function: FUN_802bdbe8
// Entry: 802bdbe8
// Size: 332 bytes

undefined4 FUN_802bdbe8(int param_1,undefined4 param_2,int param_3)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  iVar3 = FUN_80114bb0(param_1,param_3,iVar5 + 0x3ec,0,0);
  if (iVar3 == 0) {
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      bVar1 = *(byte *)(param_3 + iVar3 + 0x81);
      if (0xd < bVar1) {
        if (bVar1 == 0x10) {
          *(byte *)(iVar5 + 0x9fd) = *(byte *)(iVar5 + 0x9fd) & 0xfe;
          *(byte *)(*(int *)(param_1 + 0x54) + 0x62) =
               *(byte *)(*(int *)(param_1 + 0x54) + 0x62) | 0x20;
        }
        else if (bVar1 < 0x10) {
          *(byte *)(iVar5 + 0x9fd) = *(byte *)(iVar5 + 0x9fd) | 1;
          *(byte *)(*(int *)(param_1 + 0x54) + 0x62) =
               *(byte *)(*(int *)(param_1 + 0x54) + 0x62) & 0xdf;
        }
      }
    }
    *(uint *)(iVar5 + 0xeb8) = *(uint *)(iVar5 + 0xeb8) | 0x800000;
    (**(code **)(*DAT_803dcaa8 + 0x20))(param_1,iVar5 + 4);
    fVar2 = FLOAT_803e8304;
    *(float *)(iVar5 + 0x294) = FLOAT_803e8304;
    *(float *)(iVar5 + 0x284) = fVar2;
    *(float *)(iVar5 + 0x280) = fVar2;
    *(float *)(param_1 + 0x24) = fVar2;
    *(float *)(param_1 + 0x28) = fVar2;
    *(float *)(param_1 + 0x2c) = fVar2;
    uVar4 = 0;
  }
  else {
    uVar4 = 1;
  }
  return uVar4;
}

