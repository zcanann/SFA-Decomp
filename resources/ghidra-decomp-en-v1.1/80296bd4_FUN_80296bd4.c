// Function: FUN_80296bd4
// Entry: 80296bd4
// Size: 124 bytes

void FUN_80296bd4(int param_1,uint param_2,uint param_3)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (param_2 < 0xc) {
    if (param_3 == 0) {
      *(byte *)(iVar1 + 0x8c7) = *(byte *)(iVar1 + 0x8c7) & ~(byte)(1 << param_2);
    }
    else {
      *(byte *)(iVar1 + 0x8c7) = *(byte *)(iVar1 + 0x8c7) | (byte)(1 << param_2);
    }
    FUN_800201ac((int)(short)(&DAT_803356b4)[param_2],param_3);
  }
  return;
}

