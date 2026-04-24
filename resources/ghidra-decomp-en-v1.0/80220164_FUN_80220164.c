// Function: FUN_80220164
// Entry: 80220164
// Size: 124 bytes

void FUN_80220164(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  FUN_80036fa4(param_1,0x4a);
  puVar2 = puVar1;
  for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(puVar1 + 8); iVar3 = iVar3 + 1) {
    FUN_8002cbc4(*puVar2);
    puVar2 = puVar2 + 1;
  }
  if (puVar1[0xb] != 0) {
    FUN_8001cb3c(puVar1 + 0xb);
  }
  return;
}

