// Function: FUN_802aad44
// Entry: 802aad44
// Size: 572 bytes

/* WARNING: Removing unreachable block (ram,0x802aaf58) */

void FUN_802aad44(int param_1)

{
  int iVar1;
  int iVar2;
  float fVar3;
  float fVar4;
  undefined2 *puVar5;
  undefined4 uVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 in_f31;
  double dVar12;
  undefined2 local_88;
  undefined2 local_86;
  undefined2 local_84;
  float local_80;
  float local_7c;
  undefined4 local_78;
  float local_74;
  undefined auStack112 [64];
  longlong local_30;
  longlong local_28;
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar9 = *(int *)(param_1 + 0xb8);
  puVar5 = &DAT_803daf08;
  dVar12 = (double)*(float *)(iVar9 + 2000);
  FUN_8005d118(0,0xff,0xff,0xff,0x80);
  FUN_800799c0();
  FUN_800795e8();
  FUN_80079804();
  FUN_80078740();
  FUN_8025c688(0);
  iVar8 = 0;
  pfVar7 = (float *)&DAT_802c2bf0;
  fVar3 = FLOAT_803e7fa4 * (float)((double)FLOAT_803e80c4 - dVar12);
  iVar10 = 8;
  do {
    if (iVar8 < 4) {
      puVar5[1] = 800;
      fVar4 = FLOAT_803e7fa4;
      iVar1 = (int)(FLOAT_803e7fa4 * *pfVar7);
      *puVar5 = (short)iVar1;
      iVar2 = (int)(fVar4 * pfVar7[2]);
      puVar5[2] = (short)iVar2;
    }
    else {
      puVar5[1] = (short)(int)fVar3;
      fVar4 = FLOAT_803e7fa4;
      iVar2 = (int)(FLOAT_803e7fa4 * *pfVar7);
      *puVar5 = (short)iVar2;
      iVar1 = (int)(fVar4 * pfVar7[2]);
      puVar5[2] = (short)iVar1;
    }
    local_28 = (longlong)iVar2;
    local_30 = (longlong)iVar1;
    *(undefined *)(puVar5 + 6) = 0xff;
    *(undefined *)((int)puVar5 + 0xd) = 0;
    *(undefined *)(puVar5 + 7) = 0;
    *(undefined *)((int)puVar5 + 0xf) = 0x40;
    puVar5 = puVar5 + 8;
    pfVar7 = pfVar7 + 3;
    iVar8 = iVar8 + 1;
    iVar10 = iVar10 + -1;
  } while (iVar10 != 0);
  local_7c = *(float *)(param_1 + 0xc) - FLOAT_803dcdd8;
  local_78 = *(undefined4 *)(param_1 + 0x10);
  local_74 = *(float *)(param_1 + 0x14) - FLOAT_803dcddc;
  local_88 = *(undefined2 *)(iVar9 + 0x478);
  local_86 = 0;
  local_84 = 0;
  local_80 = FLOAT_803e7f6c;
  FUN_80021570(&local_88,auStack112);
  uVar6 = FUN_8000f54c();
  FUN_80246eb4(uVar6,auStack112,auStack112);
  FUN_8025d0a8(auStack112,0);
  FUN_8005cf8c(&DAT_803daf08,&DAT_802c2b30,0xc);
  if (FLOAT_803e80e0 <= *(float *)(iVar9 + 2000)) {
    iVar8 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -4;
    if (iVar8 < 0) {
      iVar8 = 0;
    }
    *(char *)(param_1 + 0x36) = (char)iVar8;
  }
  FUN_8025c688(1);
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  return;
}

