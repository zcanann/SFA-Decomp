// Function: FUN_80240bc4
// Entry: 80240bc4
// Size: 28 bytes

undefined4 FUN_80240bc4(uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(DAT_803dddec + (param_1 & 0xff) * 4);
  uVar1 = *puVar2;
  *puVar2 = param_2;
  return uVar1;
}

