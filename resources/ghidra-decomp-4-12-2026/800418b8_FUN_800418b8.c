// Function: FUN_800418b8
// Entry: 800418b8
// Size: 772 bytes

/* WARNING: Removing unreachable block (ram,0x80041b9c) */
/* WARNING: Removing unreachable block (ram,0x80041b94) */
/* WARNING: Removing unreachable block (ram,0x800418d0) */
/* WARNING: Removing unreachable block (ram,0x800418c8) */

void FUN_800418b8(undefined4 param_1,undefined4 param_2,uint param_3)

{
  undefined2 *puVar1;
  int *piVar2;
  float *pfVar3;
  undefined2 *puVar4;
  ushort *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_e8;
  undefined4 local_e4;
  float local_e0;
  ushort local_dc;
  undefined2 local_da;
  undefined2 local_d8;
  float local_d4;
  undefined4 local_d0;
  undefined4 local_cc;
  undefined4 local_c8;
  float afStack_c4 [3];
  float local_b8;
  undefined4 local_a8;
  float local_98;
  float afStack_84 [27];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar11 = FUN_80286840();
  puVar1 = (undefined2 *)((ulonglong)uVar11 >> 0x20);
  puVar5 = (ushort *)uVar11;
  if (FLOAT_803df684 == *(float *)(puVar1 + 4)) {
    DAT_803dd8a4 = (float *)0x0;
  }
  else {
    FUN_8002b660((int)puVar1);
    piVar2 = (int *)FUN_8002b660((int)puVar5);
    iVar8 = ((ushort)puVar1[0x58] & 7) * 0x18;
    iVar7 = *(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8;
    iVar6 = (int)*(char *)(iVar7 + *(char *)((int)puVar5 + 0xad) + 0x12);
    local_d0 = *(undefined4 *)(*(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8);
    local_cc = *(undefined4 *)(iVar7 + 4);
    local_c8 = *(undefined4 *)(iVar7 + 8);
    if (iVar6 == -1) {
      FUN_8002b554(puVar5,afStack_84,'\0');
      pfVar3 = afStack_84;
    }
    else {
      pfVar3 = (float *)FUN_80028630(piVar2,iVar6);
    }
    if ((*(byte *)(*(int *)(puVar1 + 0x28) + 0x5f) & 8) == 0) {
      local_d4 = FLOAT_803df69c;
      iVar8 = *(int *)(*(int *)(puVar5 + 0x28) + 0x2c) + iVar8;
      local_dc = *(ushort *)(iVar8 + 0xc);
      local_da = *(undefined2 *)(iVar8 + 0xe);
      local_d8 = *(undefined2 *)(iVar8 + 0x10);
      FUN_80021634(&local_dc,afStack_c4);
      FUN_80247618(pfVar3,afStack_c4,afStack_c4);
    }
    else {
      puVar4 = FUN_8000facc();
      local_d4 = *(float *)(puVar1 + 4);
      dVar10 = (double)(*(float *)(puVar1 + 6) - *(float *)(puVar4 + 6));
      dVar9 = (double)(*(float *)(puVar1 + 10) - *(float *)(puVar4 + 10));
      iVar8 = FUN_80021884();
      local_dc = (short)iVar8 + 0x8000;
      FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
      iVar8 = FUN_80021884();
      local_da = (undefined2)iVar8;
      local_d8 = puVar4[2];
      FUN_80021634(&local_dc,afStack_c4);
      local_e8 = local_b8;
      local_e4 = local_a8;
      local_e0 = local_98;
      FUN_80247bf8(pfVar3,&local_e8,&local_e8);
      local_b8 = local_e8;
      local_a8 = local_e4;
      local_98 = local_e0;
    }
    if ((param_3 & 0xff) == 0) {
      *(float *)(puVar1 + 0xc) = local_b8 + FLOAT_803dda58;
      *(undefined4 *)(puVar1 + 0xe) = local_a8;
      *(float *)(puVar1 + 0x10) = local_98 + FLOAT_803dda5c;
      if (*(int *)(puVar1 + 0x18) == 0) {
        *(undefined4 *)(puVar1 + 6) = *(undefined4 *)(puVar1 + 0xc);
        *(undefined4 *)(puVar1 + 8) = *(undefined4 *)(puVar1 + 0xe);
        *(undefined4 *)(puVar1 + 10) = *(undefined4 *)(puVar1 + 0x10);
      }
      else {
        FUN_8000e054((double)*(float *)(puVar1 + 0xc),(double)*(float *)(puVar1 + 0xe),
                     (double)*(float *)(puVar1 + 0x10),(float *)(puVar1 + 6),(float *)(puVar1 + 8),
                     (float *)(puVar1 + 10),*(int *)(puVar1 + 0x18));
      }
      FUN_8003bde0(afStack_c4,puVar1,puVar1 + 1,puVar1 + 2);
    }
    *(char *)((int)puVar1 + 0x37) =
         (char)((*(byte *)(puVar1 + 0x1b) + 1) * (uint)*(byte *)((int)puVar5 + 0x37) >> 8);
    *(undefined *)((int)puVar1 + 0xf1) = *(undefined *)((int)puVar5 + 0xf1);
    if ((puVar1[3] & 0x4000) == 0) {
      DAT_803dd8a4 = afStack_c4;
      if ((param_3 & 0xff) == 0) {
        puVar1[0x58] = puVar1[0x58] | 0x800;
        FUN_80041bbc((int)puVar1);
      }
      else {
        FUN_800417e8((int)puVar1);
      }
    }
  }
  FUN_8028688c();
  return;
}

