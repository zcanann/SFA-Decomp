// Function: FUN_801a2af8
// Entry: 801a2af8
// Size: 220 bytes

void FUN_801a2af8(undefined2 *param_1,int param_2)

{
  char cVar3;
  int iVar1;
  undefined4 uVar2;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  *(undefined4 *)(iVar4 + 0xc) = 0;
  FUN_8002b8c8(param_1,0x51);
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) = *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
  *(char *)(iVar4 + 0x10) = (char)*(undefined2 *)(param_2 + 0x1a);
  if (*(short *)(param_2 + 0x20) != -1) {
    cVar3 = FUN_8001ffb4();
    *(char *)(iVar4 + 0x11) = cVar3;
    if (cVar3 != '\0') {
      FUN_8002b884(param_1,*(undefined *)(iVar4 + 0x11));
    }
  }
  FUN_800200e8(0x2de,1);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  if (iVar1 != 0) {
    uVar2 = FUN_801a27b8(param_1,(int)*(short *)(param_2 + 0x1c));
    *(undefined4 *)(iVar4 + 0xc) = uVar2;
  }
  return;
}

