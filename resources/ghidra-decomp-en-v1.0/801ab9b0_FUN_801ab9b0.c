// Function: FUN_801ab9b0
// Entry: 801ab9b0
// Size: 212 bytes

void FUN_801ab9b0(short *param_1,int param_2)

{
  int iVar1;
  code **ppcVar2;
  
  ppcVar2 = *(code ***)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  param_1[0x58] = param_1[0x58] | 0x4000;
  iVar1 = *(int *)(param_2 + 0x14);
  if (iVar1 == 0x45f1b) {
    *ppcVar2 = FUN_801ab700;
    *(undefined2 *)(ppcVar2 + 1) = 0xf1;
  }
  else if (iVar1 < 0x45f1b) {
    if (0x45f19 < iVar1) {
      *ppcVar2 = FUN_801ab800;
      *(undefined2 *)(ppcVar2 + 1) = 0xaa;
      FUN_8002b6d8(param_1,0,0,0,0,3);
    }
  }
  else if (iVar1 < 0x45f1d) {
    *ppcVar2 = FUN_801ab700;
    *(undefined2 *)(ppcVar2 + 1) = 0xfe;
  }
  return;
}

