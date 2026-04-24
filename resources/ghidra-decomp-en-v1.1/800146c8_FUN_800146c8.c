// Function: FUN_800146c8
// Entry: 800146c8
// Size: 32 bytes

void FUN_800146c8(void)

{
  if ((DAT_803dd578 & 1) == 0) {
    return;
  }
  DAT_803dd578 = DAT_803dd578 & 0xfe;
  return;
}

