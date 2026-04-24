// Function: FUN_80156c34
// Entry: 80156c34
// Size: 168 bytes

void FUN_80156c34(undefined4 param_1,int param_2)

{
  int iVar1;
  
  if ((*(uint *)(param_2 + 0x2dc) & 0x40000000) != 0) {
    if (*(byte *)(param_2 + 0x33a) == 0) {
      *(undefined *)(param_2 + 0x33a) = 1;
    }
    else if (1 < *(byte *)(param_2 + 0x33a)) {
      *(undefined *)(param_2 + 0x33a) = 0;
    }
    iVar1 = (uint)*(byte *)(param_2 + 0x33a) * 0xc;
    FUN_8014d08c((double)*(float *)(&DAT_8031f318 + iVar1),param_1,param_2,(&DAT_8031f320)[iVar1],0,
                 0);
  }
  FUN_80156950(param_1,param_2);
  return;
}

