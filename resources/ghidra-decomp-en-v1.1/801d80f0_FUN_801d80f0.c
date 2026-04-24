// Function: FUN_801d80f0
// Entry: 801d80f0
// Size: 160 bytes

void FUN_801d80f0(short *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  *(code **)(param_1 + 0x5e) = FUN_801d76c8;
  *(undefined2 *)((int)puVar2 + 0xe) = 0x15a;
  *(undefined2 *)(puVar2 + 4) = 0x886;
  FUN_80036018((int)param_1);
  uVar1 = FUN_80020078(0x887);
  if ((uVar1 == 0) || (uVar1 = FUN_80020078(0x15a), uVar1 == 0)) {
    *(undefined *)(puVar2 + 3) = 0;
  }
  else {
    *(undefined *)(puVar2 + 3) = 1;
  }
  FUN_800201ac((int)*(short *)(puVar2 + 4),0);
  *puVar2 = 0;
  return;
}

