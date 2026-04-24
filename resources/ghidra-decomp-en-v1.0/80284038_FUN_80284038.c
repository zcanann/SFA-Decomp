// Function: FUN_80284038
// Entry: 80284038
// Size: 468 bytes

void FUN_80284038(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6)

{
  undefined4 uVar1;
  undefined *puVar2;
  
  if (param_4 == 0) {
    puVar2 = &DAT_803d3f60;
  }
  else {
    puVar2 = (undefined *)0x803d41e4;
  }
  while (uVar1 = FUN_8024377c(), 0xf < (byte)puVar2[0x281]) {
    FUN_802437a4(uVar1);
  }
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 4) = 0x2a;
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 8) = 0;
  *(uint *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0xc) = (uint)(param_4 != 0);
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x10) = param_1;
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x14) = param_2;
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x18) = param_3;
  *(undefined **)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x1c) = &LAB_80283fa0;
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x20) = param_5;
  *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x24) = param_6;
  FUN_80250d64(puVar2 + (uint)(byte)puVar2[0x280] * 0x28,
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 4),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 8),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0xc),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x10),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x14),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x18),
               *(undefined4 *)(puVar2 + (uint)(byte)puVar2[0x280] * 0x28 + 0x1c));
  puVar2[0x281] = puVar2[0x281] + '\x01';
  puVar2[0x280] =
       (char)((byte)puVar2[0x280] + 1) + (char)((int)((byte)puVar2[0x280] + 1) >> 4) * -0x10;
  FUN_802437a4(uVar1);
  return;
}

