// Function: FUN_80240be0
// Entry: 80240be0
// Size: 20 bytes

undefined4 FUN_80240be0(uint param_1)

{
  return *(undefined4 *)(DAT_803dddec + (param_1 & 0xff) * 4);
}

