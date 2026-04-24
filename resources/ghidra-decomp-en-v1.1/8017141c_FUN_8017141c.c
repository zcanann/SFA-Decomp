// Function: FUN_8017141c
// Entry: 8017141c
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x80171724) */
/* WARNING: Removing unreachable block (ram,0x8017142c) */

void FUN_8017141c(void)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  double dVar10;
  double dVar11;
  undefined8 local_58;
  undefined8 local_50;
  
  iVar1 = FUN_80286830();
  pfVar9 = (float *)&DAT_80321678;
  iVar8 = *(int *)(iVar1 + 0xb8);
  if (*(float *)(iVar8 + 4) != *(float *)(iVar8 + 8)) {
    *(float *)(iVar8 + 4) = *(float *)(iVar8 + 0xc) * FLOAT_803dc074 + *(float *)(iVar8 + 4);
    if (*(float *)(iVar8 + 0xc) <= FLOAT_803e4044) {
      if (*(float *)(iVar8 + 4) <= *(float *)(iVar8 + 8)) {
        *(float *)(iVar8 + 4) = *(float *)(iVar8 + 8);
        *(byte *)(iVar8 + 0x5c) = *(byte *)(iVar8 + 0x5c) | 1;
        *(byte *)(iVar8 + 0x5d) = *(byte *)(iVar8 + 0x5d) | 1;
        *(byte *)(iVar8 + 0x5e) = *(byte *)(iVar8 + 0x5e) | 1;
        *(byte *)(iVar8 + 0x5f) = *(byte *)(iVar8 + 0x5f) | 1;
      }
    }
    else {
      if (*(float *)(iVar8 + 8) <= *(float *)(iVar8 + 4)) {
        *(float *)(iVar8 + 4) = *(float *)(iVar8 + 8);
      }
      *(byte *)(iVar8 + 0x5c) = *(byte *)(iVar8 + 0x5c) & 0xfe;
      *(byte *)(iVar8 + 0x5d) = *(byte *)(iVar8 + 0x5d) & 0xfe;
      *(byte *)(iVar8 + 0x5e) = *(byte *)(iVar8 + 0x5e) & 0xfe;
      *(byte *)(iVar8 + 0x5f) = *(byte *)(iVar8 + 0x5f) & 0xfe;
    }
  }
  if (*(short *)(iVar1 + 0x46) == 0x836) {
    uVar2 = FUN_80022264(0x60,0x7f);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(char *)(iVar1 + 0x36) =
         (char)(int)((*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10)) *
                    (float)(local_58 - DOUBLE_803e4068));
  }
  else {
    uVar2 = FUN_80022264(0xc0,0xff);
    local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(char *)(iVar1 + 0x36) =
         (char)(int)((*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10)) *
                    (float)(local_50 - DOUBLE_803e4068));
  }
  FUN_8000b9bc((double)FLOAT_803e4040,iVar1,0x42d,
               (byte)(int)(FLOAT_803e4080 * (*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10))));
  if (*(char *)(iVar1 + 0x36) == '\0') {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
  }
  else {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
  }
  iVar7 = 0;
  pfVar5 = (float *)&DAT_80321698;
  puVar4 = &DAT_803216a8;
  puVar3 = &DAT_80321688;
  iVar6 = iVar8;
  dVar11 = DOUBLE_803e4068;
  do {
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x3c) ^ 0x80000000);
    local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x34) ^ 0x80000000);
    *(short *)(iVar6 + 0x34) =
         (short)(int)((float)(local_50 - dVar11) * FLOAT_803dc074 + (float)(local_58 - dVar11));
    if (*(short *)(iVar1 + 0x46) == 0x836) {
      dVar10 = (double)FUN_80293a9c();
      *(float *)(iVar8 + 0x24) =
           *pfVar5 * (float)(dVar10 * (double)FLOAT_803e4084 + (double)FLOAT_803e405c);
      *(undefined4 *)(iVar8 + 0x14) = *puVar4;
    }
    else {
      dVar10 = (double)FUN_80293a9c();
      *(float *)(iVar8 + 0x24) = *pfVar9 * (float)((double)FLOAT_803e405c + dVar10) * FLOAT_803e4040
      ;
      *(undefined4 *)(iVar8 + 0x14) = *puVar3;
    }
    iVar6 = iVar6 + 2;
    pfVar5 = pfVar5 + 1;
    iVar8 = iVar8 + 4;
    puVar4 = puVar4 + 1;
    pfVar9 = pfVar9 + 1;
    puVar3 = puVar3 + 1;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
  FUN_8028687c();
  return;
}

