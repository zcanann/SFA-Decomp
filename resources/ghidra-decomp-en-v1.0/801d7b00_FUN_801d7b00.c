// Function: FUN_801d7b00
// Entry: 801d7b00
// Size: 160 bytes

void FUN_801d7b00(short *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801d70d8;
  *(undefined2 *)((int)puVar2 + 0xe) = 0x15a;
  *(undefined2 *)(puVar2 + 4) = 0x886;
  FUN_80035f20();
  iVar1 = FUN_8001ffb4(0x887);
  if ((iVar1 == 0) || (iVar1 = FUN_8001ffb4(0x15a), iVar1 == 0)) {
    *(undefined *)(puVar2 + 3) = 0;
  }
  else {
    *(undefined *)(puVar2 + 3) = 1;
  }
  FUN_800200e8((int)*(short *)(puVar2 + 4),0);
  *puVar2 = 0;
  return;
}

