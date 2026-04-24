// Function: FUN_80243ec0
// Entry: 80243ec0
// Size: 28 bytes

undefined4 FUN_80243ec0(short param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(DAT_803deab8 + param_1 * 4);
  uVar1 = *puVar2;
  *puVar2 = param_2;
  return uVar1;
}

