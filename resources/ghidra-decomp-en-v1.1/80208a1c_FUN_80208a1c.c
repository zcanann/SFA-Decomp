// Function: FUN_80208a1c
// Entry: 80208a1c
// Size: 160 bytes

void FUN_80208a1c(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined2 *puVar2;
  
  puVar2 = *(undefined2 **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_802086d0;
  *(undefined *)((int)puVar2 + 7) = *(undefined *)(param_2 + 0x19);
  *puVar2 = *(undefined2 *)(param_2 + 0x1e);
  puVar2[1] = *(undefined2 *)(param_2 + 0x20);
  uVar1 = FUN_80020078((int)(short)puVar2[1]);
  if (uVar1 != 0) {
    *(undefined *)(puVar2 + 3) = 1;
  }
  puVar2[2] = 0;
  *(undefined *)(puVar2 + 4) = 0;
  param_1[0x58] = param_1[0x58] | 0x4000;
  return;
}

