// Function: FUN_8026c41c
// Entry: 8026c41c
// Size: 108 bytes

uint FUN_8026c41c(uint param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  
  for (puVar1 = DAT_803de234; puVar2 = DAT_803de230, puVar1 != (undefined4 *)0x0;
      puVar1 = (undefined4 *)*puVar1) {
    if (puVar1[3] == (param_1 & 0x7fffffff)) {
      return (uint)*(byte *)((int)puVar1 + 9) | param_1 & 0x80000000;
    }
  }
  while( true ) {
    if (puVar2 == (undefined4 *)0x0) {
      return 0xffffffff;
    }
    if (puVar2[3] == (param_1 & 0x7fffffff)) break;
    puVar2 = (undefined4 *)*puVar2;
  }
  return (uint)*(byte *)((int)puVar2 + 9) | param_1 & 0x80000000;
}

