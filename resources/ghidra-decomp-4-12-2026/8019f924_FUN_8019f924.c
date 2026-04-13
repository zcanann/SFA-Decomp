// Function: FUN_8019f924
// Entry: 8019f924
// Size: 400 bytes

void FUN_8019f924(short *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  
  FUN_80036018((int)param_1);
  FUN_80037a5c((int)param_1,4);
  *(code **)(param_1 + 0x5e) = FUN_8019ed98;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1d) << 8;
  FUN_800372f8((int)param_1,3);
  puVar2 = *(undefined4 **)(param_1 + 0x5c);
  puVar2[0x2c] = 0;
  puVar2[0x2d] = 0;
  puVar2[0x2e] = 0;
  puVar2[0x2f] = 0;
  puVar2[0x30] = 0;
  puVar2[0x31] = (uint)*(byte *)(param_2 + 0x1c);
  puVar2[0x33] = 0;
  FUN_800803f8(puVar2);
  puVar2[0x45] = 0;
  *(short *)(puVar2 + 0x34) = *param_1;
  *(undefined *)(puVar2 + 0x8b) = 0;
  puVar2[0x2a] = FLOAT_803e4ec4;
  puVar2[0x8c] = 0;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x22));
  if (uVar1 == 0) {
    puVar2[0x8d] = *(short *)(param_2 + 0x22) + -0x2fc;
    if (param_1[0x23] == 0x788) {
      puVar2[0x8d] = 0xffffffff;
      puVar2[0x8f] = FLOAT_803e4edc;
      puVar2[0x90] = &DAT_803dca98;
    }
    else {
      if (((int)puVar2[0x8d] < 0) || (4 < (int)puVar2[0x8d])) {
        puVar2[0x8c] = 3;
      }
      puVar2[0x8f] = FLOAT_803e4ef0;
      puVar2[0x90] = &DAT_803dca90;
      FUN_800372f8((int)param_1,0x20);
    }
    *(byte *)(puVar2 + 0x91) = *(byte *)(puVar2 + 0x91) & 0x7f;
  }
  else {
    FUN_80035ff8((int)param_1);
    param_1[3] = param_1[3] | 0x4000;
    *(byte *)(puVar2 + 0x8b) = *(byte *)(puVar2 + 0x8b) & 0xfe;
    FUN_8002cf80((int)param_1);
    FUN_8003709c((int)param_1,3);
  }
  return;
}

