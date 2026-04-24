// Function: FUN_800a0fd0
// Entry: 800a0fd0
// Size: 112 bytes

void FUN_800a0fd0(int param_1)

{
  int iVar1;
  undefined2 *puVar2;
  undefined2 *puVar3;
  
  puVar3 = *(undefined2 **)(param_1 + (uint)*(byte *)(param_1 + 0x130) * 4 + 0x78);
  puVar2 = *(undefined2 **)(param_1 + 0x80);
  for (iVar1 = 0; iVar1 < *(short *)(param_1 + 0xea); iVar1 = iVar1 + 1) {
    *puVar3 = *puVar2;
    puVar3[1] = puVar2[1];
    puVar3[2] = puVar2[2];
    *(undefined *)(puVar3 + 6) = *(undefined *)(puVar2 + 6);
    *(undefined *)((int)puVar3 + 0xd) = *(undefined *)((int)puVar2 + 0xd);
    *(undefined *)(puVar3 + 7) = *(undefined *)(puVar2 + 7);
    *(undefined *)((int)puVar3 + 0xf) = *(undefined *)((int)puVar2 + 0xf);
    puVar3 = puVar3 + 8;
    puVar2 = puVar2 + 8;
  }
  return;
}

