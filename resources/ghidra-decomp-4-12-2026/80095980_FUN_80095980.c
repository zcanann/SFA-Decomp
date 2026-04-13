// Function: FUN_80095980
// Entry: 80095980
// Size: 112 bytes

/* WARNING: Removing unreachable block (ram,0x800959d8) */
/* WARNING: Removing unreachable block (ram,0x80095990) */

undefined4 FUN_80095980(double param_1,float *param_2)

{
  undefined4 uVar1;
  double dVar2;
  
  if ((DAT_803dde78 == '\0') ||
     (dVar2 = FUN_802480c0(param_2,(float *)&DAT_8039b7a8),
     (double)(float)(param_1 * param_1) <= dVar2)) {
    uVar1 = 0;
  }
  else {
    uVar1 = 1;
  }
  DAT_803dde78 = 0;
  return uVar1;
}

