// Function: FUN_800280b4
// Entry: 800280b4
// Size: 336 bytes

void FUN_800280b4(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined auStack40 [4];
  uint local_24;
  undefined4 local_20 [8];
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = (int)uVar3;
  local_24 = 0;
  FUN_80048f48(0x52,&local_24,iVar2 << 2,4);
  if ((local_24 & 0x10000000) == 0) {
    local_24 = *(uint *)(DAT_803dcb4c + iVar2 * 4);
    FUN_800464c8(0x30,0,local_24,0,local_20,iVar2,1);
    FUN_800464c8(0x30,param_4 + 0x80,local_24,local_20[0],auStack40,iVar2,0);
    FUN_80048f48(0x32,param_4,
                 *(int *)(iVar1 + 0x80) + param_3 * ((*(byte *)(iVar1 + 0xf3) - 1 & 0xfffffff8) + 8)
                );
  }
  else {
    FUN_800464c8(0x51,0,local_24,0,local_20,iVar2,1);
    FUN_800464c8(0x51,param_4 + 0x80,local_24,local_20[0],auStack40,iVar2,0);
    FUN_80048f48(0x32,param_4,
                 *(int *)(iVar1 + 0x80) + param_3 * ((*(byte *)(iVar1 + 0xf3) - 1 & 0xfffffff8) + 8)
                );
  }
  FUN_80286128(param_4 + 0x80);
  return;
}

