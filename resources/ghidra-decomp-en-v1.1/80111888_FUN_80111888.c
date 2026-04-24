// Function: FUN_80111888
// Entry: 80111888
// Size: 188 bytes

void FUN_80111888(char param_1)

{
  undefined1 *puVar1;
  
  if (param_1 != DAT_803de24a) {
    if (DAT_803de249 == '\x04') {
      if (FLOAT_803e2860 == FLOAT_803dc638) {
        FUN_8000a538((int *)0xbe,1);
        FUN_8000a538((int *)0xc1,1);
      }
      else {
        puVar1 = FUN_800e81bc();
        FUN_80117e10(0,1000);
        FUN_80009a28((uint)(byte)puVar1[10],1000,1,0,0);
      }
    }
    DAT_803de249 = DAT_803de24a;
    FLOAT_803dc638 = FLOAT_803e2864;
    DAT_803de248 = 1;
    DAT_803de24a = param_1;
  }
  return;
}

