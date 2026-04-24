// Function: FUN_80264864
// Entry: 80264864
// Size: 300 bytes

int FUN_80264864(int param_1,int param_2,uint param_3)

{
  int iVar1;
  char *pcVar2;
  int *local_14 [2];
  
  if ((param_2 < 0) || (0x7e < param_2)) {
    iVar1 = -0x80;
  }
  else {
    iVar1 = FUN_8025f52c(param_1,local_14);
    if (-1 < iVar1) {
      iVar1 = FUN_80261014((int)local_14[0]);
      pcVar2 = (char *)(iVar1 + param_2 * 0x40);
      iVar1 = FUN_802634f8((int)local_14[0],pcVar2);
      if (iVar1 == -10) {
        iVar1 = FUN_80263590(pcVar2);
      }
      if (-1 < iVar1) {
        FUN_80003494(param_3 + 0x28,(uint)pcVar2,4);
        FUN_80003494(param_3 + 0x2c,(uint)(pcVar2 + 4),2);
        *(uint *)(param_3 + 0x20) = (uint)*(ushort *)(pcVar2 + 0x38) * local_14[0][3];
        FUN_80003494(param_3,(uint)(pcVar2 + 8),0x20);
        *(undefined4 *)(param_3 + 0x24) = *(undefined4 *)(pcVar2 + 0x28);
        *(char *)(param_3 + 0x2e) = pcVar2[7];
        *(undefined4 *)(param_3 + 0x30) = *(undefined4 *)(pcVar2 + 0x2c);
        *(undefined2 *)(param_3 + 0x34) = *(undefined2 *)(pcVar2 + 0x30);
        *(undefined2 *)(param_3 + 0x36) = *(undefined2 *)(pcVar2 + 0x32);
        *(undefined4 *)(param_3 + 0x38) = *(undefined4 *)(pcVar2 + 0x3c);
        FUN_8026466c((int)pcVar2,param_3);
      }
      iVar1 = FUN_8025f5e4(local_14[0],iVar1);
    }
  }
  return iVar1;
}

