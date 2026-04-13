// Function: FUN_80194db8
// Entry: 80194db8
// Size: 132 bytes

void FUN_80194db8(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = *(undefined2 *)(param_2 + 0x24);
  FUN_800372f8((int)param_1,0x23);
  FUN_800372f8((int)param_1,0x31);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x18));
  if (uVar1 != 0) {
    *(byte *)(puVar2 + 1) = *(byte *)(puVar2 + 1) & 0x7f | 0x80;
    *puVar2 = 3000;
  }
  return;
}

