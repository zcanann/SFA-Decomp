// Function: FUN_8000e738
// Entry: 8000e738
// Size: 252 bytes

/* WARNING: Removing unreachable block (ram,0x8000e810) */
/* WARNING: Removing unreachable block (ram,0x8000e808) */
/* WARNING: Removing unreachable block (ram,0x8000e800) */
/* WARNING: Removing unreachable block (ram,0x8000e7f8) */
/* WARNING: Removing unreachable block (ram,0x8000e7f0) */

void FUN_8000e738(double param_1,double param_2,double param_3,double param_4,double param_5)

{
  byte bVar1;
  int iVar2;
  undefined2 *puVar3;
  uint unaff_GQR0;
  double dVar4;
  
  bVar1 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar1 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar1 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar1 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar1 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar1 & 0x3f);
  }
  iVar2 = 0;
  puVar3 = &DAT_80338e30;
  do {
    dVar4 = FUN_80293900((double)((float)(param_3 - (double)*(float *)(puVar3 + 10)) *
                                  (float)(param_3 - (double)*(float *)(puVar3 + 10)) +
                                 (float)(param_1 - (double)*(float *)(puVar3 + 6)) *
                                 (float)(param_1 - (double)*(float *)(puVar3 + 6)) +
                                 (float)(param_2 - (double)*(float *)(puVar3 + 8)) *
                                 (float)(param_2 - (double)*(float *)(puVar3 + 8))));
    if (dVar4 < param_4) {
      *(float *)(puVar3 + 0x16) =
           (float)((double)(float)(param_5 * (double)(float)(param_4 - dVar4)) / param_4);
      *(undefined *)((int)puVar3 + 0x5d) = 0;
    }
    puVar3 = puVar3 + 0x30;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 8);
  bVar1 = (byte)(unaff_GQR0 >> 0x18);
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar1 & 0x3f));
  }
  return;
}

