// Function: FUN_801b9b80
// Entry: 801b9b80
// Size: 308 bytes

void FUN_801b9b80(int param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  undefined *puVar3;
  
  iVar1 = FUN_800e87c4();
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  else {
    *(undefined4 *)(param_1 + 0xf4) = 2;
  }
  for (uVar2 = 1; (uVar2 & 0xff) < 0x2e; uVar2 = uVar2 + 1) {
    FUN_800ea2e0(uVar2);
  }
  puVar3 = *(undefined **)(param_1 + 0xb8);
  *puVar3 = (char)*(undefined2 *)(param_2 + 0x1a);
  puVar3[1] = *puVar3;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x1e));
  puVar3[2] = puVar3[2] | iVar1 != 0;
  *(undefined4 *)(puVar3 + 0xc) = 0xd7;
  puVar3[4] = 0;
  if ((puVar3[2] & 1) == 0) {
    *puVar3 = 3;
    puVar3[3] = uRam803dbf2b;
    FUN_8004c1e4((double)FLOAT_803e4b90,uRam803dbf2b);
  }
  else {
    *puVar3 = 0;
    puVar3[3] = DAT_803dbf28;
    FUN_8004c1e4((double)FLOAT_803e4b90,DAT_803dbf28);
  }
  FUN_8000a518(0xdd,1);
  FUN_800887f8(0);
  return;
}

