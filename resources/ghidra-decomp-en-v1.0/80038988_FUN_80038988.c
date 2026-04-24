// Function: FUN_80038988
// Entry: 80038988
// Size: 1428 bytes

/* WARNING: Removing unreachable block (ram,0x80038ef4) */
/* WARNING: Removing unreachable block (ram,0x800389f8) */
/* WARNING: Removing unreachable block (ram,0x80038efc) */
/* WARNING: Could not reconcile some variable overlaps */

void FUN_80038988(int param_1,int param_2,uint param_3)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar10;
  double dVar11;
  undefined8 local_48;
  double local_40;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_48._7_1_ = (byte)(int)(FLOAT_803de998 * FLOAT_803db414);
  dVar10 = (double)FLOAT_803de99c;
  bVar1 = *(byte *)(param_2 + 0x2b);
  uVar2 = (ushort)(int)(FLOAT_803de998 * FLOAT_803db414);
  dVar11 = dVar10;
  if (bVar1 == 3) {
    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
    *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803de9c0) + FLOAT_803db414);
    if ((int)(short)(ushort)*(byte *)(param_2 + 0x2d) - (int)(short)(uVar2 & 0xff) < 0) {
      *(undefined *)(param_2 + 0x2b) = 0;
      local_48._7_1_ = *(byte *)(param_2 + 0x2d);
    }
    *(byte *)(param_2 + 0x2d) = *(char *)(param_2 + 0x2d) - (byte)local_48;
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803de9c0) + FLOAT_803db414);
      if (0xff < (uint)((int)(short)(ushort)*(byte *)(param_2 + 0x2d) + (int)(short)(uVar2 & 0xff)))
      {
        local_48._7_1_ = 0xff - *(byte *)(param_2 + 0x2d);
        *(undefined *)(param_2 + 0x2b) = 2;
      }
      *(byte *)(param_2 + 0x2d) = *(char *)(param_2 + 0x2d) + (byte)local_48;
    }
    else if (bVar1 == 0) {
      local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_48 - DOUBLE_803de9c0) + FLOAT_803db414);
      *(undefined *)(param_2 + 0x2d) = 0;
      if ((param_3 & 1) != 0) {
        iVar4 = FUN_800221a0(0,100);
        if (iVar4 == 1) {
          bVar1 = *(byte *)(param_2 + 0x2b);
          if (bVar1 == 3) {
            *(undefined *)(param_2 + 0x2b) = 1;
          }
          else if ((bVar1 < 3) && (bVar1 == 0)) {
            *(undefined *)(param_2 + 0x2b) = 1;
            *(undefined *)(param_2 + 0x2c) = 0;
            *(undefined *)(param_2 + 0x2d) = 0;
          }
        }
        else {
          iVar4 = FUN_800221a0(0,0x4b);
          if (iVar4 == 1) {
            iVar4 = FUN_800221a0(0,1);
            if (iVar4 == 0) {
              *(undefined *)(param_2 + 0x2b) = 4;
            }
            else {
              *(undefined *)(param_2 + 0x2b) = 5;
            }
          }
        }
      }
    }
    else {
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803de9c0) + FLOAT_803db414);
      iVar4 = FUN_800221a0(0,100);
      if (iVar4 == 1) {
        bVar1 = *(byte *)(param_2 + 0x2b);
        if (bVar1 != 3) {
          if (bVar1 < 3) {
            if (bVar1 != 0) {
              *(undefined *)(param_2 + 0x2b) = 3;
            }
          }
          else if (bVar1 < 6) {
            *(undefined *)(param_2 + 0x2b) = 0;
          }
        }
      }
    }
  }
  else if (bVar1 == 5) {
    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
    *(char *)(param_2 + 0x2c) =
         (char)(int)(FLOAT_803de9a0 * FLOAT_803db414 + (float)(local_40 - DOUBLE_803de9c0));
    *(undefined *)(param_2 + 0x2d) = 0xff;
    dVar11 = (double)FLOAT_803de9a4;
    iVar4 = FUN_800221a0(0,0x19);
    if (iVar4 == 1) {
      bVar1 = *(byte *)(param_2 + 0x2b);
      if (bVar1 != 3) {
        if (bVar1 < 3) {
          if (bVar1 != 0) {
            *(undefined *)(param_2 + 0x2b) = 3;
          }
        }
        else if (bVar1 < 6) {
          *(undefined *)(param_2 + 0x2b) = 0;
        }
      }
    }
  }
  else if (bVar1 < 5) {
    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
    *(char *)(param_2 + 0x2c) =
         (char)(int)(FLOAT_803de9a0 * FLOAT_803db414 + (float)(local_40 - DOUBLE_803de9c0));
    *(undefined *)(param_2 + 0x2d) = 0xff;
    dVar10 = (double)FLOAT_803de9a4;
    iVar4 = FUN_800221a0(0,0x19);
    if (iVar4 == 1) {
      bVar1 = *(byte *)(param_2 + 0x2b);
      if (bVar1 != 3) {
        if (bVar1 < 3) {
          if (bVar1 != 0) {
            *(undefined *)(param_2 + 0x2b) = 3;
          }
        }
        else if (bVar1 < 6) {
          *(undefined *)(param_2 + 0x2b) = 0;
        }
      }
    }
  }
  local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
  dVar9 = (double)FUN_802943f4((double)(FLOAT_803de9ac * (float)(local_40 - DOUBLE_803de9c0)));
  local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2d));
  dVar9 = (double)(((float)((double)FLOAT_803de9a8 * dVar9) * (float)(local_48 - DOUBLE_803de9c0)) /
                  FLOAT_803de9b0);
  iVar4 = 0;
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 != 0) {
    iVar6 = 0;
    iVar7 = 0;
    for (uVar3 = (uint)*(byte *)(iVar5 + 0x5a); uVar3 != 0; uVar3 = uVar3 - 1) {
      if ((*(char *)(*(int *)(iVar5 + 0x10) + *(char *)(param_1 + 0xad) + iVar6 + 1) != -1) &&
         (*(char *)(*(int *)(iVar5 + 0x10) + iVar6) == '\x05')) {
        iVar4 = *(int *)(param_1 + 0x6c) + iVar7;
      }
      iVar6 = *(char *)(iVar5 + 0x55) + iVar6 + 1;
      iVar7 = iVar7 + 0x12;
    }
  }
  *(short *)(iVar4 + 2) = (short)(int)((FLOAT_803de9b4 * (float)(dVar11 * dVar9)) / FLOAT_803de9b8);
  iVar4 = 0;
  iVar5 = *(int *)(param_1 + 0x50);
  if (iVar5 != 0) {
    iVar6 = 0;
    iVar7 = 0;
    for (uVar3 = (uint)*(byte *)(iVar5 + 0x5a); uVar3 != 0; uVar3 = uVar3 - 1) {
      if ((*(char *)(*(int *)(iVar5 + 0x10) + *(char *)(param_1 + 0xad) + iVar6 + 1) != -1) &&
         (*(char *)(*(int *)(iVar5 + 0x10) + iVar6) == '\x04')) {
        iVar4 = *(int *)(param_1 + 0x6c) + iVar7;
      }
      iVar6 = *(char *)(iVar5 + 0x55) + iVar6 + 1;
      iVar7 = iVar7 + 0x12;
    }
  }
  *(short *)(iVar4 + 2) = -(short)(int)((FLOAT_803de9b4 * (float)(dVar10 * dVar9)) / FLOAT_803de9b8)
  ;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  return;
}

