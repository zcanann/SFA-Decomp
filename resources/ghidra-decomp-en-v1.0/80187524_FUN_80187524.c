// Function: FUN_80187524
// Entry: 80187524
// Size: 284 bytes

void FUN_80187524(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  undefined uVar4;
  undefined4 uVar3;
  undefined4 *puVar5;
  undefined4 *puVar6;
  
  puVar5 = *(undefined4 **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_8018728c;
  iVar2 = FUN_8002b9ec();
  if (*(short *)(iVar2 + 0x46) == 0) {
    *(undefined2 *)(puVar5 + 8) = 0x5d6;
  }
  else {
    *(undefined2 *)(puVar5 + 8) = 0x13d;
  }
  *(undefined *)(puVar5 + 7) = 0;
  uVar4 = FUN_8001ffb4((int)*(short *)(puVar5 + 8));
  *(undefined *)((int)puVar5 + 0x1d) = uVar4;
  if (*(char *)(param_2 + 0x19) == '\x01') {
    if (*(char *)((int)puVar5 + 0x1d) != '\0') {
      *(undefined *)(puVar5 + 7) = 1;
      uVar3 = FUN_801871c8(param_1);
      *puVar5 = uVar3;
    }
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  else {
    bVar1 = *(byte *)((int)puVar5 + 0x1d);
    if (5 < bVar1) {
      bVar1 = 6;
    }
    *(byte *)(puVar5 + 7) = bVar1;
    puVar6 = puVar5;
    for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(puVar5 + 7); iVar2 = iVar2 + 1) {
      uVar3 = FUN_801871c8(param_1);
      *puVar6 = uVar3;
      puVar6 = puVar6 + 1;
    }
  }
  return;
}

