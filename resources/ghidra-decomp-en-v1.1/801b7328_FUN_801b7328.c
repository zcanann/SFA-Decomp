// Function: FUN_801b7328
// Entry: 801b7328
// Size: 848 bytes

/* WARNING: Removing unreachable block (ram,0x801b7654) */
/* WARNING: Removing unreachable block (ram,0x801b764c) */
/* WARNING: Removing unreachable block (ram,0x801b7644) */
/* WARNING: Removing unreachable block (ram,0x801b7348) */
/* WARNING: Removing unreachable block (ram,0x801b7340) */
/* WARNING: Removing unreachable block (ram,0x801b7338) */

void FUN_801b7328(uint param_1)

{
  char cVar1;
  int iVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  undefined auStack_78 [8];
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  
  psVar3 = *(short **)(param_1 + 0xb8);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  cVar1 = *(char *)((int)psVar3 + 3);
  if (cVar1 == '\x01') {
    *(float *)(psVar3 + 2) = *(float *)(psVar3 + 2) + FLOAT_803dc074;
    if (FLOAT_803e56dc < *(float *)(psVar3 + 2)) {
      *(undefined *)((int)psVar3 + 3) = 2;
      FUN_8000bb38(0,0x109);
      FUN_8000bb38(param_1,0x47b);
      iVar2 = 0x1e;
      dVar5 = (double)FLOAT_803e56e0;
      dVar6 = (double)FLOAT_803e56e4;
      dVar4 = DOUBLE_803e56e8;
      do {
        uStack_5c = FUN_80022264(0xffffff9c,100);
        uStack_5c = uStack_5c ^ 0x80000000;
        local_60 = 0x43300000;
        local_6c = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_5c) - dVar4));
        uStack_54 = FUN_80022264(0,0x15e);
        uStack_54 = uStack_54 ^ 0x80000000;
        local_58 = 0x43300000;
        local_68 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_54) - dVar4));
        uStack_4c = FUN_80022264(0xffffff9c,100);
        uStack_4c = uStack_4c ^ 0x80000000;
        local_50 = 0x43300000;
        local_64 = (float)(dVar5 * (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - dVar4));
        local_70 = (float)dVar6;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fb,auStack_78,2,0xffffffff,0);
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fc,auStack_78,2,0xffffffff,0);
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    uStack_4c = FUN_80022264(0xffffff9c,100);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_6c = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e56e8);
    uStack_54 = FUN_80022264(0,0x15e);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    local_68 = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e56e8);
    uStack_5c = FUN_80022264(0xffffff9c,100);
    uStack_5c = uStack_5c ^ 0x80000000;
    local_60 = 0x43300000;
    local_64 = FLOAT_803e56e0 * (float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e56e8);
    local_70 = FLOAT_803e56e4;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x7fc,auStack_78,2,0xffffffff,0);
  }
  else if (cVar1 < '\x01') {
    if (-1 < cVar1) {
      if (*(char *)(psVar3 + 1) < '\x01') {
        if ((int)*psVar3 != 0xffffffff) {
          FUN_800201ac((int)*psVar3,1);
          FUN_80035ff8(param_1);
          *(undefined *)((int)psVar3 + 3) = 1;
          *(float *)(psVar3 + 2) = FLOAT_803e56d8;
        }
      }
      else {
        iVar2 = FUN_8002ba84();
        if (iVar2 != 0) {
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar2 + 0x68) + 0x28))(iVar2,param_1,1,4);
          }
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
        }
      }
    }
  }
  else if (cVar1 < '\x03') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

