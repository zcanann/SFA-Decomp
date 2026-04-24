// Function: FUN_80015ebc
// Entry: 80015ebc
// Size: 776 bytes

/* WARNING: Removing unreachable block (ram,0x800161a4) */
/* WARNING: Removing unreachable block (ram,0x8001619c) */
/* WARNING: Removing unreachable block (ram,0x80015ed4) */
/* WARNING: Removing unreachable block (ram,0x80015ecc) */

void FUN_80015ebc(void)

{
  int iVar1;
  int iVar2;
  bool bVar3;
  undefined uVar4;
  undefined uVar5;
  undefined uVar6;
  undefined4 uVar7;
  undefined4 *puVar8;
  int iVar9;
  undefined *puVar10;
  double in_f30;
  double dVar11;
  double in_f31;
  double dVar12;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar13;
  float local_68;
  uint local_64 [3];
  undefined4 local_58;
  uint uStack_54;
  undefined8 local_50;
  longlong local_48;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar13 = FUN_80286834();
  uVar7 = (undefined4)((ulonglong)uVar13 >> 0x20);
  iVar2 = (int)uVar13 * 0x20;
  puVar10 = &DAT_802c7b80 + iVar2;
  bVar3 = false;
  if ((DAT_803dd640 != 1) && ((&DAT_802c7b92)[iVar2] = (&DAT_802c7b90)[iVar2], DAT_803dd63c == 0)) {
    FUN_8001bf44(0,uVar7,(int)puVar10);
  }
  local_64[2] = (uint)*(ushort *)(&DAT_802c7b88 + iVar2);
  local_64[1] = 0x43300000;
  puVar8 = (undefined4 *)
           FUN_80016cd4((double)(float)((double)CONCAT44(0x43300000,local_64[2]) - DOUBLE_803df370),
                        (double)*(float *)(&DAT_802c7b8c + iVar2),uVar7,local_64,&local_68);
  if (puVar8 == (undefined4 *)0x0) {
    local_64[2] = local_64[0] ^ 0x80000000;
    local_64[1] = 0x43300000;
    uStack_54 = (int)*(short *)(&DAT_802c7b9a + iVar2) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar9 = (int)(local_68 * (float)((double)CONCAT44(0x43300000,local_64[2]) - DOUBLE_803df378) +
                 (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df378));
    local_50 = (double)(longlong)iVar9;
    *(short *)(&DAT_802c7b9a + iVar2) = (short)iVar9;
  }
  else {
    if (DAT_803dd5ec == 0) {
      if (DAT_803dd63c == 0) {
        FUN_8005524c(0,0,(int)*(short *)(&DAT_802c7b94 + iVar2),
                     (int)*(short *)(&DAT_802c7b96 + iVar2),
                     (int)*(short *)(&DAT_802c7b94 + iVar2) +
                     (uint)*(ushort *)(&DAT_802c7b88 + iVar2),
                     (int)*(short *)(&DAT_802c7b96 + iVar2) +
                     (uint)*(ushort *)(&DAT_802c7b8a + iVar2));
      }
    }
    else {
      FUN_8005524c(0,0,0,0,0x280,0x1e0);
    }
    FLOAT_803dd620 = *(float *)(&DAT_802c7b8c + iVar2);
    dVar12 = DOUBLE_803df378;
    for (iVar9 = 0; iVar9 < (int)local_64[0]; iVar9 = iVar9 + 1) {
      if ((iVar9 == local_64[0] - 1) && ((&DAT_802c7b92)[iVar2] == '\x03')) {
        (&DAT_802c7b92)[iVar2] = 0;
        bVar3 = true;
      }
      uVar6 = DAT_803dd627;
      uVar5 = DAT_803dd626;
      uVar4 = DAT_803dd625;
      if ((DAT_803dd604 == 1) && (DAT_803dd63c == 0)) {
        dVar11 = (double)FLOAT_803dd620;
        DAT_803dd627 = DAT_803dd612;
        DAT_803dd626 = DAT_803dd611;
        DAT_803dd625 = DAT_803dd610;
        local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_802c7b98 + iVar2) ^ 0x80000000);
        uStack_54 = (int)*(short *)(&DAT_802c7b9a + iVar2) ^ 0x80000000;
        local_58 = 0x43300000;
        FUN_80017508((double)(float)(local_50 - DOUBLE_803df378),
                     (double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803df378),
                     (double)local_68,*puVar8,puVar10,1);
        FLOAT_803dd620 = (float)dVar11;
      }
      local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_802c7b98 + iVar2) ^ 0x80000000);
      uStack_54 = (int)*(short *)(&DAT_802c7b9a + iVar2) ^ 0x80000000;
      local_58 = 0x43300000;
      DAT_803dd625 = uVar4;
      DAT_803dd626 = uVar5;
      DAT_803dd627 = uVar6;
      FUN_80017508((double)(float)(local_50 - dVar12),
                   (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar12),(double)local_68
                   ,*puVar8,puVar10,0);
      local_64[2] = (int)*(short *)(&DAT_802c7b9a + iVar2) ^ 0x80000000;
      local_64[1] = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,local_64[2]) - dVar12) + local_68);
      local_48 = (longlong)iVar1;
      *(short *)(&DAT_802c7b9a + iVar2) = (short)iVar1;
      if (bVar3) {
        (&DAT_802c7b92)[iVar2] = 3;
      }
      puVar8 = puVar8 + 1;
    }
    if (DAT_803dd63c == 0) {
      FUN_8000f0d8();
    }
  }
  FUN_80286880();
  return;
}

