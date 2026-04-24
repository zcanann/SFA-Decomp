// Function: FUN_802717b0
// Entry: 802717b0
// Size: 188 bytes

undefined4
FUN_802717b0(undefined4 param_1,uint param_2,uint param_3,undefined4 param_4,undefined4 param_5)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  iVar1 = FUN_802751b8();
  if (iVar1 != 0) {
    if ((param_2 & 0xff) == 0xff) {
      param_2 = (uint)*(byte *)(iVar1 + 6);
    }
    if ((param_3 & 0xff) == 0xff) {
      param_3 = (uint)*(byte *)(iVar1 + 7);
    }
    uVar2 = FUN_8026feec(*(undefined2 *)(iVar1 + 2),*(undefined *)(iVar1 + 5),
                         *(undefined *)(iVar1 + 4),*(byte *)(iVar1 + 8) | 0x80,param_2,param_3,0xff,
                         0xff,0,0,0xff,*(undefined *)(iVar1 + 9),0,param_4,param_5);
  }
  return uVar2;
}

