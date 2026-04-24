// Function: FUN_802437c8
// Entry: 802437c8
// Size: 28 bytes

undefined4 FUN_802437c8(short param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(DAT_803dde38 + param_1 * 4);
  uVar1 = *puVar2;
  *puVar2 = param_2;
  return uVar1;
}

