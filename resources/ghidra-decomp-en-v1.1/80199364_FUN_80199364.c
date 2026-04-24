// Function: FUN_80199364
// Entry: 80199364
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x80199500) */
/* WARNING: Removing unreachable block (ram,0x80199374) */

void FUN_80199364(void)

{
  float fVar1;
  float fVar2;
  char cVar3;
  int iVar4;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps31_1;
  undefined8 uVar17;
  float local_48;
  float local_44;
  float local_40;
  longlong local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar17 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar17 >> 0x20);
  iVar5 = *(int *)(iVar4 + 0xb8);
  fVar2 = *(float *)(iVar5 + 0x18);
  dVar10 = (double)*(float *)(iVar5 + 0x14);
  fVar1 = (float)(dVar10 * (double)*(float *)(iVar5 + 0x24));
  dVar9 = (double)*(float *)(iVar5 + 0xc);
  dVar11 = (double)*(float *)(iVar5 + 0x1c);
  dVar8 = (double)*(float *)(iVar5 + 0x10);
  dVar14 = (double)(float)(dVar8 * (double)*(float *)(iVar5 + 0x20));
  dVar15 = (double)(fVar2 + fVar1 + (float)(dVar9 * dVar11 + dVar14));
  dVar16 = (double)(fVar2 + (float)(dVar10 * (double)*(float *)(iVar5 + 0x30) +
                                   (double)(float)(dVar9 * (double)*(float *)(iVar5 + 0x28) +
                                                  (double)(float)(dVar8 * (double)*(float *)(iVar5 +
                                                                                            0x2c))))
                   );
  dVar6 = (double)FLOAT_803e4d70;
  if (dVar6 <= dVar16) {
    if (dVar6 <= dVar15) {
      cVar3 = -2;
    }
    else {
      cVar3 = -1;
    }
  }
  else if (dVar6 <= dVar15) {
    cVar3 = '\x01';
  }
  else {
    cVar3 = '\x02';
  }
  if ((cVar3 == '\x01') || (cVar3 == -1)) {
    dVar15 = (double)(float)((double)*(float *)(iVar5 + 0x28) - dVar11);
    dVar12 = (double)(float)((double)*(float *)(iVar5 + 0x2c) - (double)*(float *)(iVar5 + 0x20));
    dVar13 = (double)(float)((double)*(float *)(iVar5 + 0x30) - (double)*(float *)(iVar5 + 0x24));
    dVar6 = (double)((((float)(-dVar9 * dVar11 - dVar14) - fVar1) - fVar2) /
                    (float)(dVar10 * dVar13 +
                           (double)(float)(dVar9 * dVar15 + (double)(float)(dVar8 * dVar12))));
    local_48 = (float)(dVar6 * dVar15 + dVar11);
    local_44 = (float)(dVar6 * dVar12 + (double)*(float *)(iVar5 + 0x20));
    local_40 = (float)(dVar6 * dVar13 + (double)*(float *)(iVar5 + 0x24));
    FUN_80247bf8((float *)(iVar5 + 0x38),&local_48,&local_48);
    dVar6 = (double)*(float *)(iVar5 + 0x34);
    dVar8 = -dVar6;
    if ((dVar8 <= (double)local_48) &&
       ((((double)local_48 <= dVar6 && (dVar8 <= (double)local_44)) && ((double)local_44 <= dVar6)))
       ) {
      uVar7 = FUN_8007d858();
      local_38 = (longlong)(int)dVar16;
      FUN_8019992c(uVar7,dVar8,dVar9,dVar10,dVar11,dVar15,dVar12,dVar13,iVar4,(int)uVar17,(int)cVar3
                   ,(int)dVar16,in_r7,in_r8,in_r9,in_r10);
    }
  }
  FUN_8028688c();
  return;
}

