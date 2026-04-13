// Function: FUN_801a30ac
// Entry: 801a30ac
// Size: 220 bytes

void FUN_801a30ac(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar3 + 0xc) = 0;
  FUN_8002b9a0((int)param_1,'Q');
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
  *(char *)(iVar3 + 0x10) = (char)*(undefined2 *)(param_2 + 0x1a);
  if ((int)*(short *)(param_2 + 0x20) != 0xffffffff) {
    uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x20));
    *(char *)(iVar3 + 0x11) = (char)uVar1;
    if ((uVar1 & 0xff) != 0) {
      FUN_8002b95c((int)param_1,(uint)*(byte *)(iVar3 + 0x11));
    }
  }
  FUN_800201ac(0x2de,1);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    uVar2 = FUN_801a2d6c((int)param_1,(int)*(short *)(param_2 + 0x1c));
    *(undefined4 *)(iVar3 + 0xc) = uVar2;
  }
  return;
}

