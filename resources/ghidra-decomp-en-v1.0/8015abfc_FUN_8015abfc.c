// Function: FUN_8015abfc
// Entry: 8015abfc
// Size: 196 bytes

void FUN_8015abfc(int param_1,int param_2)

{
  int iVar1;
  undefined *puVar2;
  
  puVar2 = (&PTR_DAT_8031fd48)[(uint)*(ushort *)(param_2 + 0x338) * 2];
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    if (*(short *)(param_1 + 0xa0) == 7) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
    else if (*(short *)(param_1 + 0xa0) != 0) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
    FUN_8014d08c((double)*(float *)(puVar2 + iVar1),param_1,param_2,puVar2[iVar1 + 8],0,0);
  }
  FUN_8015a77c(param_1,param_2);
  return;
}

