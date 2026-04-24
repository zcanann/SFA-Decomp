// Function: FUN_80014acc
// Entry: 80014acc
// Size: 108 bytes

/* WARNING: Removing unreachable block (ram,0x80014b20) */
/* WARNING: Removing unreachable block (ram,0x80014adc) */

void FUN_80014acc(double param_1)

{
  int iVar1;
  
  if ((DAT_803dd589 != '\0') && (iVar1 = FUN_800206e4(), iVar1 == 1)) {
    FUN_8024f374(0,1);
    if (param_1 < (double)FLOAT_803dd58c) {
      param_1 = (double)FLOAT_803dd58c;
    }
    FLOAT_803dd58c = (float)param_1;
  }
  return;
}

