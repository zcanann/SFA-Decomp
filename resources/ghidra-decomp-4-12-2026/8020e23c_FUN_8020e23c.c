// Function: FUN_8020e23c
// Entry: 8020e23c
// Size: 332 bytes

/* WARNING: Removing unreachable block (ram,0x8020e368) */
/* WARNING: Removing unreachable block (ram,0x8020e360) */
/* WARNING: Removing unreachable block (ram,0x8020e254) */
/* WARNING: Removing unreachable block (ram,0x8020e24c) */

void FUN_8020e23c(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5,
                 int param_6,undefined4 param_7)

{
  uint uVar1;
  int iVar2;
  double in_f30;
  double dVar3;
  double in_f31;
  double dVar4;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar5;
  ushort local_88 [4];
  float local_80;
  float local_7c;
  float local_78;
  undefined auStack_74 [6];
  undefined2 local_6e;
  float local_68;
  float local_64;
  float local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar5 = FUN_80286830();
  dVar3 = (double)FLOAT_803e72f4;
  dVar4 = DOUBLE_803e7308;
  for (iVar2 = 0; iVar2 < param_6; iVar2 = iVar2 + 1) {
    local_80 = (float)dVar3;
    uStack_54 = FUN_80022264((uint)uVar5,param_3);
    uStack_54 = uStack_54 ^ 0x80000000;
    local_58 = 0x43300000;
    local_7c = (float)((double)CONCAT44(0x43300000,uStack_54) - dVar4);
    uStack_4c = FUN_80022264(param_4,param_5);
    uStack_4c = uStack_4c ^ 0x80000000;
    local_50 = 0x43300000;
    local_78 = (float)((double)CONCAT44(0x43300000,uStack_4c) - dVar4);
    local_88[0] = 0;
    local_88[1] = 0;
    uVar1 = FUN_80022264(0xffff8001,0x7fff);
    local_88[2] = (ushort)uVar1;
    FUN_80021b8c(local_88,&local_80);
    local_68 = local_80;
    local_64 = local_7c;
    local_60 = local_78;
    local_6e = 100;
    (**(code **)(*DAT_803dd708 + 8))
              ((int)((ulonglong)uVar5 >> 0x20),param_7,auStack_74,2,0xffffffff,0);
  }
  FUN_8028687c();
  return;
}

