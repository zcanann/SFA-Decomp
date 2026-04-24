// Function: FUN_801e62f0
// Entry: 801e62f0
// Size: 104 bytes

undefined4 FUN_801e62f0(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  FUN_8002b9ec();
  uVar2 = 0;
  if ((*(short *)(&DAT_80327fd8 + param_2 * 0xc) != -1) && (iVar1 = FUN_8001ffb4(), iVar1 != 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

