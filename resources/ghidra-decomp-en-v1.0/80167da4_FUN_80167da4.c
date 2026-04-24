// Function: FUN_80167da4
// Entry: 80167da4
// Size: 152 bytes

undefined4 FUN_80167da4(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_1 + 0xb8) + 0x40c);
  bVar1 = *(char *)(param_2 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_80030334((double)FLOAT_803e3060,param_1,(int)DAT_80320400,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    *(undefined *)(iVar2 + 0x4a) = 4;
  }
  *(undefined4 *)(param_2 + 0x2a0) =
       *(undefined4 *)(&DAT_80320404 + (uint)*(byte *)(iVar2 + 0x4a) * 4);
  *(undefined *)(param_2 + 0x34d) = 1;
  return 0;
}

