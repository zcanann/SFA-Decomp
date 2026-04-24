// Function: FUN_80038a80
// Entry: 80038a80
// Size: 1428 bytes

/* WARNING: Removing unreachable block (ram,0x80038ff4) */
/* WARNING: Removing unreachable block (ram,0x80038fec) */
/* WARNING: Removing unreachable block (ram,0x80038a98) */
/* WARNING: Removing unreachable block (ram,0x80038a90) */
/* WARNING: Removing unreachable block (ram,0x80038af0) */

void FUN_80038a80(int param_1,int param_2,uint param_3)

{
  byte bVar1;
  ushort uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 local_48;
  undefined8 local_40;
  
  local_48._7_1_ = (byte)(int)(FLOAT_803df618 * FLOAT_803dc074);
  dVar9 = (double)FLOAT_803df61c;
  bVar1 = *(byte *)(param_2 + 0x2b);
  uVar2 = (ushort)(int)(FLOAT_803df618 * FLOAT_803dc074);
  dVar10 = dVar9;
  if (bVar1 == 3) {
    local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
    *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803df640) + FLOAT_803dc074);
    if ((int)(short)(ushort)*(byte *)(param_2 + 0x2d) - (int)(short)(uVar2 & 0xff) < 0) {
      *(undefined *)(param_2 + 0x2b) = 0;
      local_48._7_1_ = *(byte *)(param_2 + 0x2d);
    }
    *(byte *)(param_2 + 0x2d) = *(char *)(param_2 + 0x2d) - (byte)local_48;
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      local_40 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803df640) + FLOAT_803dc074);
      if (0xff < (uint)((int)(short)(ushort)*(byte *)(param_2 + 0x2d) + (int)(short)(uVar2 & 0xff)))
      {
        local_48._7_1_ = 0xff - *(byte *)(param_2 + 0x2d);
        *(undefined *)(param_2 + 0x2b) = 2;
      }
      *(byte *)(param_2 + 0x2d) = *(char *)(param_2 + 0x2d) + (byte)local_48;
    }
    else if (bVar1 == 0) {
      local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2c));
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_48 - DOUBLE_803df640) + FLOAT_803dc074);
      *(undefined *)(param_2 + 0x2d) = 0;
      if ((param_3 & 1) != 0) {
        uVar3 = FUN_80022264(0,100);
        if (uVar3 == 1) {
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
          uVar3 = FUN_80022264(0,0x4b);
          if (uVar3 == 1) {
            uVar3 = FUN_80022264(0,1);
            if (uVar3 == 0) {
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
      *(char *)(param_2 + 0x2c) = (char)(int)((float)(local_40 - DOUBLE_803df640) + FLOAT_803dc074);
      uVar3 = FUN_80022264(0,100);
      if (uVar3 == 1) {
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
         (char)(int)(FLOAT_803df620 * FLOAT_803dc074 + (float)(local_40 - DOUBLE_803df640));
    *(undefined *)(param_2 + 0x2d) = 0xff;
    dVar10 = (double)FLOAT_803df624;
    uVar3 = FUN_80022264(0,0x19);
    if (uVar3 == 1) {
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
         (char)(int)(FLOAT_803df620 * FLOAT_803dc074 + (float)(local_40 - DOUBLE_803df640));
    *(undefined *)(param_2 + 0x2d) = 0xff;
    dVar9 = (double)FLOAT_803df624;
    uVar3 = FUN_80022264(0,0x19);
    if (uVar3 == 1) {
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
  dVar8 = (double)FUN_80294b54();
  local_48 = (double)CONCAT44(0x43300000,(uint)*(byte *)(param_2 + 0x2d));
  dVar8 = (double)(((float)((double)FLOAT_803df628 * dVar8) * (float)(local_48 - DOUBLE_803df640)) /
                  FLOAT_803df630);
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
  *(short *)(iVar4 + 2) = (short)(int)((FLOAT_803df634 * (float)(dVar10 * dVar8)) / FLOAT_803df638);
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
  *(short *)(iVar4 + 2) = -(short)(int)((FLOAT_803df634 * (float)(dVar9 * dVar8)) / FLOAT_803df638);
  return;
}

