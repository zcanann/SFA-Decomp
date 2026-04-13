// Function: FUN_8028479c
// Entry: 8028479c
// Size: 468 bytes

void FUN_8028479c(undefined4 param_1,undefined4 param_2,undefined4 param_3,int param_4,
                 undefined4 param_5,undefined4 param_6)

{
  undefined *puVar1;
  
  if (param_4 == 0) {
    puVar1 = &DAT_803d4bc0;
  }
  else {
    puVar1 = (undefined *)0x803d4e44;
  }
  while (FUN_80243e74(), 0xf < (byte)puVar1[0x281]) {
    FUN_80243e9c();
  }
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 4) = 0x2a;
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 8) = 0;
  *(uint *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0xc) = (uint)(param_4 != 0);
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x10) = param_1;
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x14) = param_2;
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x18) = param_3;
  *(undefined **)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x1c) = &LAB_80284704;
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x20) = param_5;
  *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x24) = param_6;
  FUN_802514c8((undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28),
               *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 4),
               *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 8),
               *(int *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0xc),
               *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x10),
               *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x14),
               *(undefined4 *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x18),
               *(int *)(puVar1 + (uint)(byte)puVar1[0x280] * 0x28 + 0x1c));
  puVar1[0x281] = puVar1[0x281] + '\x01';
  puVar1[0x280] =
       (char)((byte)puVar1[0x280] + 1) + (char)((int)((byte)puVar1[0x280] + 1) >> 4) * -0x10;
  FUN_80243e9c();
  return;
}

