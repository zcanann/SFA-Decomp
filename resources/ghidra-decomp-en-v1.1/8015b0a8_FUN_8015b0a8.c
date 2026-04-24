// Function: FUN_8015b0a8
// Entry: 8015b0a8
// Size: 196 bytes

void FUN_8015b0a8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9,int param_10)

{
  int iVar1;
  undefined *puVar2;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  
  puVar2 = (&PTR_DAT_80320998)[(uint)*(ushort *)(param_10 + 0x338) * 2];
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  if ((*(uint *)(param_10 + 0x2dc) & 0x40000000) != 0) {
    if (*(short *)(param_9 + 0xa0) == 7) {
      *(undefined *)(param_10 + 0x33a) = 1;
    }
    else if (*(short *)(param_9 + 0xa0) != 0) {
      *(undefined *)(param_10 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_10 + 0x33a) * 0xc;
    FUN_8014d504((double)*(float *)(puVar2 + iVar1),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,param_10,(uint)(byte)puVar2[iVar1 + 8],0,0,in_r8,in_r9,in_r10);
  }
  FUN_8015ac28(param_9,param_10);
  return;
}

