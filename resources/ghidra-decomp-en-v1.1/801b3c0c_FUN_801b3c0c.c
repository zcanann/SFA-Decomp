// Function: FUN_801b3c0c
// Entry: 801b3c0c
// Size: 264 bytes

void FUN_801b3c0c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  int iVar2;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801b3a0c;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  puVar3[1] = (char)*(undefined2 *)(param_2 + 0x1a);
  *puVar3 = (char)*(undefined2 *)(param_2 + 0x1c);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  puVar3[2] = (char)uVar1;
  if (puVar3[2] == '\x01') {
    iVar2 = FUN_8005b478((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8));
    iVar2 = FUN_8005b068(iVar2);
    if (iVar2 != 0) {
      FUN_801b38f8(iVar2,1,(uint)(byte)puVar3[1]);
      FUN_801b38f8(iVar2,0,(byte)puVar3[1] + 1);
    }
  }
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

