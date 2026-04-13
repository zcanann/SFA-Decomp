// Function: FUN_802412bc
// Entry: 802412bc
// Size: 28 bytes

undefined4 FUN_802412bc(uint param_1,undefined4 param_2)

{
  undefined4 uVar1;
  undefined4 *puVar2;
  
  puVar2 = (undefined4 *)(DAT_803dea6c + (param_1 & 0xff) * 4);
  uVar1 = *puVar2;
  *puVar2 = param_2;
  return uVar1;
}

