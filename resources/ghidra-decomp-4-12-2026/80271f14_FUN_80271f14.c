// Function: FUN_80271f14
// Entry: 80271f14
// Size: 188 bytes

undefined4 FUN_80271f14(undefined2 param_1,byte param_2,uint param_3,undefined param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  
  uVar2 = 0xffffffff;
  iVar1 = FUN_8027591c(param_1);
  if (iVar1 != 0) {
    if (param_2 == 0xff) {
      param_2 = *(byte *)(iVar1 + 6);
    }
    if ((param_3 & 0xff) == 0xff) {
      param_3 = (uint)*(byte *)(iVar1 + 7);
    }
    uVar2 = FUN_80270650((uint)*(ushort *)(iVar1 + 2),(uint)*(byte *)(iVar1 + 5),
                         (uint)*(byte *)(iVar1 + 4),*(byte *)(iVar1 + 8) | 0x80,param_2,param_3,0xff
                         ,0xff,0,0,0xff,*(undefined *)(iVar1 + 9),0,param_4,param_5);
  }
  return uVar2;
}

