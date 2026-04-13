// Function: FUN_801abf64
// Entry: 801abf64
// Size: 212 bytes

void FUN_801abf64(short *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[0x58] = param_1[0x58] | 0x4000;
  iVar1 = *(int *)(param_2 + 0x14);
  if (iVar1 == 0x45f1b) {
    *puVar2 = FUN_801abcb4;
    *(undefined2 *)(puVar2 + 1) = 0xf1;
  }
  else if (iVar1 < 0x45f1b) {
    if (0x45f19 < iVar1) {
      *puVar2 = FUN_801abdb4;
      *(undefined2 *)(puVar2 + 1) = 0xaa;
      FUN_8002b7b0((int)param_1,0,0,0,'\0','\x03');
    }
  }
  else if (iVar1 < 0x45f1d) {
    *puVar2 = FUN_801abcb4;
    *(undefined2 *)(puVar2 + 1) = 0xfe;
  }
  return;
}

