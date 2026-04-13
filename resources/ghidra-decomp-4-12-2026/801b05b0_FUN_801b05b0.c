// Function: FUN_801b05b0
// Entry: 801b05b0
// Size: 696 bytes

/* WARNING: Removing unreachable block (ram,0x801b0848) */
/* WARNING: Removing unreachable block (ram,0x801b0840) */
/* WARNING: Removing unreachable block (ram,0x801b05c8) */
/* WARNING: Removing unreachable block (ram,0x801b05c0) */

void FUN_801b05b0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  uint uVar1;
  int iVar2;
  int *piVar3;
  undefined4 in_r9;
  undefined4 in_r10;
  int *piVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  ushort local_6c;
  undefined2 local_6a;
  undefined2 local_68;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  if (param_9[0x23] == 0x1fa) {
    local_78 = DAT_802c2a98;
    local_74 = DAT_802c2a9c;
    local_70 = DAT_802c2aa0;
    local_68 = 0;
    uVar1 = FUN_80022264(0xffffd120,12000);
    local_6a = (undefined2)uVar1;
    uVar1 = FUN_80022264(0,0xfffe);
    local_6c = (ushort)uVar1;
    FUN_80021b8c(&local_6c,&local_78);
    param_9[0x7a] = 0;
    param_9[0x7b] = 0x4b;
    *(float *)(param_9 + 0x12) = local_78;
    *(undefined4 *)(param_9 + 0x14) = local_74;
    *(undefined4 *)(param_9 + 0x16) = local_70;
    *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * FLOAT_803e546c;
  }
  else {
    *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
    piVar4 = *(int **)(param_9 + 0x5c);
    uStack_4c = (int)*(short *)(param_10 + 0x1a) ^ 0x80000000;
    local_50 = 0x43300000;
    dVar7 = (double)(FLOAT_803e5470 *
                    (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e5480));
    uStack_44 = (int)*(short *)(param_10 + 0x1c) ^ 0x80000000;
    local_48 = 0x43300000;
    dVar6 = (double)(FLOAT_803e5470 *
                    (float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e5480));
    piVar4[2] = *(int *)(param_9 + 8);
    piVar4[3] = *(int *)(param_10 + 0x14);
    *(undefined4 *)(param_10 + 0x14) = 0xffffffff;
    uStack_3c = (int)*param_9 ^ 0x80000000;
    local_40 = 0x43300000;
    dVar5 = (double)FUN_802945e0();
    *(float *)(param_9 + 0x12) = (float)(dVar6 * -dVar5);
    *(float *)(param_9 + 0x14) = (float)dVar7;
    uStack_34 = (int)*param_9 ^ 0x80000000;
    local_38 = 0x43300000;
    dVar5 = (double)FUN_80294964();
    *(float *)(param_9 + 0x16) = (float)(dVar6 * -dVar5);
    if (*(int *)(param_9 + 0x2a) != 0) {
      *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6a) = 0;
    }
    iVar2 = *(int *)(param_9 + 0x32);
    if (iVar2 != 0) {
      *(uint *)(iVar2 + 0x30) = *(uint *)(iVar2 + 0x30) | 0x810;
    }
    iVar2 = FUN_8002e1ac(piVar4[3]);
    *piVar4 = iVar2;
    *(byte *)(piVar4 + 4) = *(byte *)(piVar4 + 4) | 0x10;
    FUN_80035ff8((int)param_9);
    param_9[0x58] = param_9[0x58] | 0x2000;
    piVar3 = FUN_8001f58c((int)param_9,'\x01');
    piVar4[1] = (int)piVar3;
    if (piVar4[1] != 0) {
      FUN_8001dbf0(piVar4[1],2);
      FUN_8001dbb4(piVar4[1],0xff,0x80,0,0);
      dVar5 = (double)FLOAT_803e549c;
      FUN_8001dcfc((double)FLOAT_803e5498,dVar5,piVar4[1]);
      FUN_8001d7f4((double)FLOAT_803e54a0,dVar5,param_3,param_4,param_5,param_6,param_7,param_8,
                   piVar4[1],0,0xff,0x80,0,100,in_r9,in_r10);
      FUN_8001d7d8((double)FLOAT_803e54a0,piVar4[1]);
    }
  }
  return;
}

