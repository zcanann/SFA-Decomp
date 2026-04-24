// Function: FUN_80167f58
// Entry: 80167f58
// Size: 192 bytes

undefined4 FUN_80167f58(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  bVar1 = *(char *)(param_2 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      iVar2 = FUN_800221a0(0,4);
      FUN_80030334((double)FLOAT_803e3060,param_1,(int)*(short *)(&DAT_803203f8 + iVar2 * 2),0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    FUN_80035f20(param_1);
    *(undefined *)(iVar3 + 0x4a) = 4;
  }
  *(undefined4 *)(param_2 + 0x2a0) =
       *(undefined4 *)(&DAT_80320404 + (uint)*(byte *)(iVar3 + 0x4a) * 4);
  *(undefined *)(param_2 + 0x34d) = 1;
  return 0;
}

