// Function: FUN_801b3658
// Entry: 801b3658
// Size: 264 bytes

void FUN_801b3658(undefined2 *param_1,int param_2)

{
  undefined uVar2;
  int iVar1;
  undefined *puVar3;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_801b3458;
  puVar3 = *(undefined **)(param_1 + 0x5c);
  puVar3[1] = (char)*(undefined2 *)(param_2 + 0x1a);
  *puVar3 = (char)*(undefined2 *)(param_2 + 0x1c);
  uVar2 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  puVar3[2] = uVar2;
  if (puVar3[2] == '\x01') {
    FUN_8005b2fc((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                 (double)*(float *)(param_1 + 10));
    iVar1 = FUN_8005aeec();
    if (iVar1 != 0) {
      FUN_801b3344(iVar1,1,puVar3[1]);
      FUN_801b3344(iVar1,0,(byte)puVar3[1] + 1);
    }
  }
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
       *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

