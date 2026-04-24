// Function: FUN_80253cdc
// Entry: 80253cdc
// Size: 236 bytes

undefined4 FUN_80253cdc(int param_1,uint param_2,undefined4 param_3,int param_4,undefined4 param_5)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = param_1 * 0x40;
  FUN_80243e74();
  if (((*(uint *)(&DAT_803af06c + iVar1) & 3) == 0) && ((*(uint *)(&DAT_803af06c + iVar1) & 4) != 0)
     ) {
    *(undefined4 *)(&DAT_803af064 + iVar1) = param_5;
    if (*(int *)(&DAT_803af064 + iVar1) != 0) {
      FUN_80254000(param_1,0,1,0);
      FUN_802442c4(0x200000 >> param_1 * 3);
    }
    iVar3 = param_1 * 0x14;
    *(uint *)(&DAT_803af06c + iVar1) = *(uint *)(&DAT_803af06c + iVar1) | 1;
    *(uint *)(&DAT_cc006804 + iVar3) = param_2 & 0x3ffffe0;
    *(undefined4 *)(&DAT_cc006808 + iVar3) = param_3;
    *(uint *)(&DAT_cc00680c + iVar3) = param_4 << 2 | 3;
    FUN_80243e9c();
    uVar2 = 1;
  }
  else {
    FUN_80243e9c();
    uVar2 = 0;
  }
  return uVar2;
}

