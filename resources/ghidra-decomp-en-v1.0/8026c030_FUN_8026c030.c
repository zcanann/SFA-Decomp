// Function: FUN_8026c030
// Entry: 8026c030
// Size: 244 bytes

undefined4 * FUN_8026c030(undefined4 param_1,byte param_2)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  
  puVar1 = DAT_803de21c;
  if (DAT_803de21c != (undefined4 *)0x0) {
    DAT_803de21c = (undefined4 *)*DAT_803de21c;
    if (DAT_803de21c != (undefined4 *)0x0) {
      DAT_803de21c[1] = 0;
    }
    puVar1[3] = param_1;
    *(byte *)(puVar1 + 4) = param_2;
    *(undefined *)((int)puVar1 + 0x11) =
         *(undefined *)(DAT_803de218 + (uint)param_2 * 0x38 + 0x1518);
    puVar2 = *(undefined4 **)(DAT_803de218 + (uint)*(byte *)((int)puVar1 + 0x11) * 4 + 0xe64);
    puVar4 = (undefined4 *)0x0;
    while (puVar3 = puVar2, puVar3 != (undefined4 *)0x0) {
      if ((int)puVar1[3] < (int)puVar3[3]) {
        *puVar1 = puVar3;
        puVar1[1] = puVar4;
        if (puVar4 == (undefined4 *)0x0) {
          *(undefined4 **)(DAT_803de218 + (uint)*(byte *)((int)puVar1 + 0x11) * 4 + 0xe64) = puVar1;
        }
        else {
          *puVar4 = puVar1;
        }
        puVar3[1] = puVar1;
        return puVar1;
      }
      puVar4 = puVar3;
      puVar2 = (undefined4 *)*puVar3;
    }
    puVar1[1] = puVar4;
    if (puVar4 == (undefined4 *)0x0) {
      *(undefined4 **)(DAT_803de218 + (uint)*(byte *)((int)puVar1 + 0x11) * 4 + 0xe64) = puVar1;
    }
    else {
      *puVar4 = puVar1;
    }
    *puVar1 = 0;
  }
  return puVar1;
}

