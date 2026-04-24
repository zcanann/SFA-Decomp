// Function: FUN_8000c6e0
// Entry: 8000c6e0
// Size: 748 bytes

/* WARNING: Removing unreachable block (ram,0x8000c9a8) */
/* WARNING: Removing unreachable block (ram,0x8000c9a0) */
/* WARNING: Removing unreachable block (ram,0x8000c998) */
/* WARNING: Removing unreachable block (ram,0x8000c990) */

void FUN_8000c6e0(uint *param_1)

{
  float fVar1;
  int iVar2;
  undefined2 *puVar3;
  int iVar4;
  uint uVar5;
  byte bVar6;
  uint unaff_GQR0;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  float local_78;
  float local_74;
  float local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined8 local_60;
  
  bVar6 = (byte)(unaff_GQR0 >> 8);
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar6 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar6 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar6 & 0x3f);
  }
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf(bVar6 & 0x3f);
  }
  puVar3 = FUN_8000facc();
  if (((puVar3 != (undefined2 *)0x0) && (param_1 != (uint *)0x0)) &&
     (*(char *)(param_1 + 1) != '\0')) {
    uStack_64 = (uint)*(byte *)((int)param_1 + 7);
    local_68 = 0x43300000;
    dVar7 = (double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803df208;
    dVar8 = (double)(float)dVar7;
    iVar2 = (int)dVar7;
    local_60._7_1_ = (byte)iVar2;
    bVar6 = (byte)local_60;
    dVar10 = (double)(float)param_1[8];
    dVar9 = (double)(float)param_1[9];
    local_60 = (double)(longlong)iVar2;
    dVar7 = FUN_8000cbe0((float *)(param_1 + 3),&local_78);
    if (dVar7 <= (double)(float)((double)FLOAT_803df218 * dVar9)) {
      FUN_8000c9cc();
      FUN_8000c9cc();
      FUN_8000c9cc();
      if (dVar7 <= (double)FLOAT_803df21c) {
        if (*(char *)((int)param_1 + 6) != '\0') {
          bVar6 = 0;
        }
        FUN_80272f0c(*param_1,7,bVar6);
      }
      else {
        if (dVar10 <= dVar7) {
          if (dVar7 <= dVar9) {
            uVar5 = (uint)(dVar8 * (double)(FLOAT_803df1f4 -
                                           (float)(dVar7 - dVar10) / (float)(dVar9 - dVar10)));
            if ((int)uVar5 < 1) {
              uVar5 = 1;
            }
            else {
              local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
              if (dVar8 < (double)(float)(local_60 - DOUBLE_803df200)) {
                uVar5 = (uint)dVar8;
              }
            }
          }
          else {
            uVar5 = 1;
          }
        }
        else {
          uVar5 = (uint)dVar8;
        }
        bVar6 = (byte)uVar5;
        fVar1 = (float)((double)FLOAT_803df220 / dVar7);
        local_78 = local_78 * fVar1;
        local_74 = local_74 * fVar1;
        local_70 = local_70 * fVar1;
        iVar2 = (int)(FLOAT_803df228 * local_78 + FLOAT_803df224);
        if (iVar2 < 0x80) {
          if (iVar2 < 0) {
            iVar2 = 0;
          }
        }
        else {
          iVar2 = 0x7f;
        }
        iVar4 = (int)(FLOAT_803df228 * local_70 + FLOAT_803df224);
        local_60 = (double)(longlong)iVar4;
        if (iVar4 < 0x80) {
          if (iVar4 < 0) {
            iVar4 = 0;
          }
        }
        else {
          iVar4 = 0x7f;
        }
        FUN_80272f0c(*param_1,10,(byte)iVar2);
        FUN_80272f0c(*param_1,0x83,(byte)iVar4);
        if (*(char *)((int)param_1 + 6) != '\0') {
          bVar6 = 0;
        }
        FUN_80272f0c(*param_1,7,bVar6);
      }
    }
    else {
      FUN_80272fcc(*param_1);
      *param_1 = 0xffffffff;
    }
  }
  bVar6 = (byte)(unaff_GQR0 >> 0x18);
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar6 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar6 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar6 & 0x3f));
  }
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-(bVar6 & 0x3f));
  }
  return;
}

