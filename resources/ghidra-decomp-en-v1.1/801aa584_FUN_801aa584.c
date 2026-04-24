// Function: FUN_801aa584
// Entry: 801aa584
// Size: 308 bytes

/* WARNING: Removing unreachable block (ram,0x801aa698) */
/* WARNING: Removing unreachable block (ram,0x801aa594) */

void FUN_801aa584(void)

{
  char cVar1;
  uint uVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  byte bVar7;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps31_1;
  undefined8 uVar10;
  int aiStack_38 [12];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar10 = FUN_8028683c();
  uVar2 = (uint)((ulonglong)uVar10 >> 0x20);
  iVar6 = (int)uVar10;
  cVar1 = '\0';
  uVar3 = FUN_80020078(0x1c0);
  if (uVar3 != 0) {
    puVar4 = FUN_80037048(0x3f,aiStack_38);
    dVar9 = (double)FLOAT_803e52b0;
    for (bVar7 = 0; bVar7 < 4; bVar7 = bVar7 + 1) {
      iVar5 = FUN_80036f50(5,puVar4[bVar7],(float *)0x0);
      dVar8 = FUN_80021730((float *)(puVar4[bVar7] + 0x18),(float *)(iVar5 + 0x18));
      if (dVar9 < dVar8) {
        cVar1 = cVar1 + '\x01';
      }
    }
  }
  if (cVar1 == '\0') {
    if (*(char *)(iVar6 + 1) != '\0') {
      FUN_8000dbb0();
      *(undefined *)(iVar6 + 1) = 0;
    }
  }
  else {
    if (*(char *)(iVar6 + 1) == '\0') {
      FUN_8000dcdc(uVar2,0x223);
      *(undefined *)(iVar6 + 1) = 1;
    }
    FUN_8000b9bc((double)FLOAT_803e52b4,uVar2,0x223,cVar1 * '\x0f' + 0x28);
  }
  FUN_80286888();
  return;
}

