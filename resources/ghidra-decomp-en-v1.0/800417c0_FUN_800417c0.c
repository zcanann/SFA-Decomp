// Function: FUN_800417c0
// Entry: 800417c0
// Size: 772 bytes

/* WARNING: Removing unreachable block (ram,0x80041a9c) */
/* WARNING: Removing unreachable block (ram,0x80041aa4) */

void FUN_800417c0(undefined4 param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f30;
  double dVar8;
  undefined8 in_f31;
  double dVar9;
  undefined8 uVar10;
  float local_e8;
  undefined4 local_e4;
  float local_e0;
  short local_dc;
  undefined2 local_da;
  undefined2 local_d8;
  float local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  undefined auStack196 [12];
  float local_b8;
  undefined4 local_a8;
  float local_98;
  undefined auStack132 [108];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar10 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar3 = (int)uVar10;
  if (FLOAT_803dea04 == *(float *)(iVar1 + 8)) {
    DAT_803dcc24 = (undefined *)0x0;
  }
  else {
    FUN_8002b588();
    FUN_8002b588(iVar3);
    iVar5 = *(int *)(*(int *)(iVar3 + 0x50) + 0x2c);
    iVar6 = (*(ushort *)(iVar1 + 0xb0) & 7) * 0x18;
    iVar4 = iVar5 + iVar6;
    local_d0 = *(undefined4 *)(iVar5 + iVar6);
    local_cc = *(undefined4 *)(iVar4 + 4);
    local_c8 = *(undefined4 *)(iVar4 + 8);
    if (*(char *)(iVar4 + *(char *)(iVar3 + 0xad) + 0x12) == -1) {
      FUN_8002b47c(iVar3,auStack132,0);
      puVar2 = auStack132;
    }
    else {
      puVar2 = (undefined *)FUN_8002856c();
    }
    if ((*(byte *)(*(int *)(iVar1 + 0x50) + 0x5f) & 8) == 0) {
      local_d4 = FLOAT_803dea1c;
      iVar6 = *(int *)(*(int *)(iVar3 + 0x50) + 0x2c) + iVar6;
      local_dc = *(short *)(iVar6 + 0xc);
      local_da = *(undefined2 *)(iVar6 + 0xe);
      local_d8 = *(undefined2 *)(iVar6 + 0x10);
      FUN_80021570(&local_dc,auStack196);
      FUN_80246eb4(puVar2,auStack196,auStack196);
    }
    else {
      iVar6 = FUN_8000faac();
      local_d4 = *(float *)(iVar1 + 8);
      dVar9 = (double)(*(float *)(iVar1 + 0xc) - *(float *)(iVar6 + 0xc));
      dVar8 = (double)(*(float *)(iVar1 + 0x14) - *(float *)(iVar6 + 0x14));
      local_dc = FUN_800217c0(dVar9,dVar8);
      local_dc = local_dc + -0x8000;
      uVar10 = FUN_802931a0((double)(float)(dVar9 * dVar9 + (double)(float)(dVar8 * dVar8)));
      local_da = FUN_800217c0((double)(*(float *)(iVar1 + 0x10) - *(float *)(iVar6 + 0x10)),uVar10);
      local_d8 = *(undefined2 *)(iVar6 + 4);
      FUN_80021570(&local_dc,auStack196);
      local_e8 = local_b8;
      local_e4 = local_a8;
      local_e0 = local_98;
      FUN_80247494(puVar2,&local_e8,&local_e8);
      local_b8 = local_e8;
      local_a8 = local_e4;
      local_98 = local_e0;
    }
    if ((param_3 & 0xff) == 0) {
      *(float *)(iVar1 + 0x18) = local_b8 + FLOAT_803dcdd8;
      *(undefined4 *)(iVar1 + 0x1c) = local_a8;
      *(float *)(iVar1 + 0x20) = local_98 + FLOAT_803dcddc;
      if (*(int *)(iVar1 + 0x30) == 0) {
        *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar1 + 0x18);
        *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar1 + 0x1c);
        *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar1 + 0x20);
      }
      else {
        FUN_8000e034((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                     (double)*(float *)(iVar1 + 0x20),iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14);
      }
      FUN_8003bce8(auStack196,iVar1,iVar1 + 2,iVar1 + 4);
    }
    *(char *)(iVar1 + 0x37) =
         (char)((*(byte *)(iVar1 + 0x36) + 1) * (uint)*(byte *)(iVar3 + 0x37) >> 8);
    *(undefined *)(iVar1 + 0xf1) = *(undefined *)(iVar3 + 0xf1);
    if ((*(ushort *)(iVar1 + 6) & 0x4000) == 0) {
      DAT_803dcc24 = auStack196;
      if ((param_3 & 0xff) == 0) {
        *(ushort *)(iVar1 + 0xb0) = *(ushort *)(iVar1 + 0xb0) | 0x800;
        FUN_80041ac4(iVar1);
      }
      else {
        FUN_800416f0(iVar1);
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  FUN_80286128();
  return;
}

