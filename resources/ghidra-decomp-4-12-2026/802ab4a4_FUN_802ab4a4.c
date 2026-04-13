// Function: FUN_802ab4a4
// Entry: 802ab4a4
// Size: 572 bytes

/* WARNING: Removing unreachable block (ram,0x802ab6b8) */
/* WARNING: Removing unreachable block (ram,0x802ab4b4) */

void FUN_802ab4a4(int param_1)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  undefined2 *puVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  double dVar10;
  ushort local_88 [4];
  float local_80;
  float local_7c;
  undefined4 local_78;
  float local_74;
  float afStack_70 [16];
  longlong local_30;
  longlong local_28;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  puVar5 = &DAT_803dbb68;
  dVar10 = (double)*(float *)(iVar8 + 2000);
  FUN_8005d294(0,0xff,0xff,0xff,0x80);
  FUN_80079b3c();
  FUN_80079764();
  FUN_80079980();
  FUN_800788bc();
  FUN_8025cdec(0);
  iVar7 = 0;
  pfVar6 = (float *)&DAT_802c3370;
  fVar3 = FLOAT_803e8c3c * (float)((double)FLOAT_803e8d5c - dVar10);
  iVar9 = 8;
  do {
    if (iVar7 < 4) {
      puVar5[1] = 800;
      fVar4 = FLOAT_803e8c3c;
      iVar1 = (int)(FLOAT_803e8c3c * *pfVar6);
      *puVar5 = (short)iVar1;
      iVar2 = (int)(fVar4 * pfVar6[2]);
      puVar5[2] = (short)iVar2;
    }
    else {
      puVar5[1] = (short)(int)fVar3;
      fVar4 = FLOAT_803e8c3c;
      iVar2 = (int)(FLOAT_803e8c3c * *pfVar6);
      *puVar5 = (short)iVar2;
      iVar1 = (int)(fVar4 * pfVar6[2]);
      puVar5[2] = (short)iVar1;
    }
    local_28 = (longlong)iVar2;
    local_30 = (longlong)iVar1;
    *(undefined *)(puVar5 + 6) = 0xff;
    *(undefined *)((int)puVar5 + 0xd) = 0;
    *(undefined *)(puVar5 + 7) = 0;
    *(undefined *)((int)puVar5 + 0xf) = 0x40;
    puVar5 = puVar5 + 8;
    pfVar6 = pfVar6 + 3;
    iVar7 = iVar7 + 1;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  local_7c = *(float *)(param_1 + 0xc) - FLOAT_803dda58;
  local_78 = *(undefined4 *)(param_1 + 0x10);
  local_74 = *(float *)(param_1 + 0x14) - FLOAT_803dda5c;
  local_88[0] = *(ushort *)(iVar8 + 0x478);
  local_88[1] = 0;
  local_88[2] = 0;
  local_80 = FLOAT_803e8c04;
  FUN_80021634(local_88,afStack_70);
  pfVar6 = (float *)FUN_8000f56c();
  FUN_80247618(pfVar6,afStack_70,afStack_70);
  FUN_8025d80c(afStack_70,0);
  FUN_8005d108(-0x7fc24498,-0x7fd3cd50,0xc);
  if (FLOAT_803e8d78 <= *(float *)(iVar8 + 2000)) {
    iVar7 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803dc070 * -4;
    if (iVar7 < 0) {
      iVar7 = 0;
    }
    *(char *)(param_1 + 0x36) = (char)iVar7;
  }
  FUN_8025cdec(1);
  return;
}

