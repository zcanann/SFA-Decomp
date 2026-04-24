// Function: FUN_800072c4
// Entry: 800072c4
// Size: 552 bytes

/* WARNING: Removing unreachable block (ram,0x800073a8) */
/* WARNING: Removing unreachable block (ram,0x80007328) */
/* WARNING: Removing unreachable block (ram,0x80007428) */

double FUN_800072c4(void)

{
  float fVar1;
  uint uVar2;
  short *unaff_r25;
  double dVar3;
  double dVar4;
  double dVar5;
  undefined4 uVar6;
  undefined local_28 [40];
  
  uVar6 = __psq_l0(local_28,0x70007);
  dVar3 = (double)CONCAT44(uVar6,0x3f800000);
  fVar1 = (float)(dVar3 * dVar3);
  dVar5 = (double)(float)(dVar3 * (double)(fVar1 * (fVar1 * (fVar1 * FLOAT_803de534 + FLOAT_803de538
                                                            ) + FLOAT_803de53c) + FLOAT_803de540));
  dVar4 = (double)(fVar1 * (fVar1 * (fVar1 * (fVar1 * FLOAT_803de520 + FLOAT_803de524) +
                                    FLOAT_803de528) + FLOAT_803de52c) + FLOAT_803de530);
  uVar2 = ((int)*unaff_r25 >> 1) + 0x2000U & 0xc000;
  dVar3 = dVar5;
  if ((uVar2 != 0) && (dVar3 = dVar4, uVar2 != 0x4000)) {
    if (uVar2 == 0x8000) {
      dVar3 = -dVar5;
    }
    else {
      dVar3 = -dVar4;
    }
  }
  __psq_l0(local_28,0x70007);
  __psq_l0(local_28,0x70007);
  return dVar3;
}

