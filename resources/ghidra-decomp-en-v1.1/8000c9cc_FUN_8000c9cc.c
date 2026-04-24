// Function: FUN_8000c9cc
// Entry: 8000c9cc
// Size: 532 bytes

/* WARNING: Removing unreachable block (ram,0x8000cbbc) */
/* WARNING: Removing unreachable block (ram,0x8000cbb4) */
/* WARNING: Removing unreachable block (ram,0x8000cbac) */
/* WARNING: Removing unreachable block (ram,0x8000cba4) */
/* WARNING: Removing unreachable block (ram,0x8000cb9c) */
/* WARNING: Removing unreachable block (ram,0x8000cb94) */
/* WARNING: Removing unreachable block (ram,0x8000cb8c) */
/* WARNING: Removing unreachable block (ram,0x8000cb84) */
/* WARNING: Removing unreachable block (ram,0x8000cb7c) */
/* WARNING: Removing unreachable block (ram,0x8000cb74) */

void FUN_8000c9cc(void)

{
  byte bVar1;
  float *in_r6;
  uint unaff_GQR0;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  
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
  dVar11 = (double)*in_r6;
  dVar10 = (double)in_r6[1];
  dVar9 = (double)in_r6[2];
  dVar2 = (double)FUN_802945e0();
  dVar3 = (double)FUN_802945e0();
  dVar4 = (double)FUN_802945e0();
  dVar5 = (double)FUN_80294964();
  dVar6 = (double)FUN_80294964();
  dVar7 = (double)FUN_80294964();
  dVar8 = (double)((float)(dVar11 * dVar5) + (float)(dVar9 * dVar2));
  dVar5 = (double)((float)(dVar9 * dVar5) - (float)(dVar11 * dVar2));
  dVar2 = (double)((float)(dVar10 * dVar6) - (float)(dVar5 * dVar3));
  *in_r6 = (float)(dVar8 * dVar7) - (float)(dVar2 * dVar4);
  in_r6[1] = (float)(dVar2 * dVar7) + (float)(dVar8 * dVar4);
  in_r6[2] = (float)(dVar5 * dVar6) + (float)(dVar10 * dVar3);
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

