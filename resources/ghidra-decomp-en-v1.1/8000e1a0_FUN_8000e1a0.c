// Function: FUN_8000e1a0
// Entry: 8000e1a0
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x8000e318) */

void FUN_8000e1a0(void)

{
  int iVar1;
  byte bVar2;
  bool bVar3;
  float *pfVar4;
  undefined4 *puVar5;
  ushort *puVar6;
  short *psVar7;
  char cVar8;
  uint unaff_GQR0;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  undefined8 uVar10;
  undefined4 local_58 [4];
  short local_48;
  short local_46;
  short local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  undefined4 local_8;
  float fStack_4;
  
  bVar2 = (byte)unaff_GQR0 & 7;
  if ((unaff_GQR0 & 0x3f00) == 0) {
    dVar9 = 1.0;
  }
  else {
    dVar9 = (double)ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  if (bVar2 == 4 || bVar2 == 6) {
    local_8 = (float)CONCAT13((char)(dVar9 * in_f31),
                              CONCAT12((char)(dVar9 * in_ps31_1),local_8._2_2_));
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    local_8 = (float)CONCAT22((short)(dVar9 * in_f31),(short)(dVar9 * in_ps31_1));
  }
  else {
    local_8 = (float)in_f31;
    fStack_4 = (float)in_ps31_1;
  }
  uVar10 = FUN_8028683c();
  iVar1 = (int)uVar10 * 0x40;
  pfVar4 = (float *)(iVar1 + -0x7fcc7b90);
  bVar3 = false;
  cVar8 = '\0';
  puVar5 = local_58;
  for (puVar6 = (ushort *)((ulonglong)uVar10 >> 0x20); puVar6 != (ushort *)0x0;
      puVar6 = *(ushort **)(puVar6 + 0x18)) {
    *puVar5 = puVar6;
    puVar5 = puVar5 + 1;
    cVar8 = cVar8 + '\x01';
    dVar9 = (double)*(float *)(puVar6 + 4);
    if ((puVar6[0x58] & 8) == 0) {
      *(float *)(puVar6 + 4) = FLOAT_803df270;
    }
    if (bVar3) {
      FUN_80021fac((float *)&DAT_80338c30,puVar6);
      FUN_800224c8((int)pfVar4,-0x7fcc73d0,pfVar4);
    }
    else {
      FUN_80021fac(pfVar4,puVar6);
    }
    *(float *)(puVar6 + 4) = (float)dVar9;
    bVar3 = true;
  }
  puVar5 = local_58 + cVar8;
  while ('\0' < cVar8) {
    puVar5 = puVar5 + -1;
    cVar8 = cVar8 + -1;
    psVar7 = (short *)*puVar5;
    local_3c = -*(float *)(psVar7 + 6);
    local_38 = -*(float *)(psVar7 + 8);
    local_34 = -*(float *)(psVar7 + 10);
    if ((psVar7[0x58] & 8U) == 0) {
      local_40 = FLOAT_803df270;
    }
    else {
      local_40 = FLOAT_803df270 / *(float *)(psVar7 + 4);
    }
    local_48 = -*psVar7;
    local_46 = -psVar7[1];
    local_44 = -psVar7[2];
    FUN_80021c64((float *)(iVar1 + -0x7fcc8310),(int)&local_48);
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  FUN_80286888();
  return;
}

