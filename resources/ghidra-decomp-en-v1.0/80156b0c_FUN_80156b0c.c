// Function: FUN_80156b0c
// Entry: 80156b0c
// Size: 296 bytes

void FUN_80156b0c(int param_1,int param_2)

{
  int iVar1;
  
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6e) = 10;
  *(undefined *)(*(int *)(param_1 + 0x54) + 0x6f) = 1;
  if (((*(uint *)(param_2 + 0x2dc) & 0x80000000) != 0) && (*(byte *)(param_2 + 0x33a) < 2)) {
    *(undefined *)(param_2 + 0x33a) = 1;
    *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x40000000;
  }
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    *(char *)(param_2 + 0x33a) = *(char *)(param_2 + 0x33a) + '\x01';
    if (10 < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 3;
    }
    if (*(ushort *)(param_2 + 0x2a0) < 4) {
      iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
      FUN_8014d08c((double)*(float *)(&DAT_8031f318 + iVar1),param_1,param_2,(&DAT_8031f320)[iVar1],
                   0,0);
    }
    else {
      iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
      FUN_8014d08c((double)*(float *)(&DAT_8031f318 + iVar1),param_1,param_2,(&DAT_8031f321)[iVar1],
                   0,0);
    }
  }
  FUN_80156950(param_1,param_2);
  return;
}

