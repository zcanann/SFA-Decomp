// Function: FUN_801bb68c
// Entry: 801bb68c
// Size: 276 bytes

/* WARNING: Removing unreachable block (ram,0x801bb780) */
/* WARNING: Removing unreachable block (ram,0x801bb69c) */

undefined4
FUN_801bb68c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)

{
  ushort *puVar1;
  undefined *puVar2;
  undefined *puVar3;
  int iVar4;
  undefined4 in_r10;
  undefined auStack_28 [2];
  undefined auStack_26 [2];
  ushort local_24 [6];
  
  *(float *)(param_10 + 0x280) = FLOAT_803e5870;
  if (((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27a) != '\0')) ||
     (*(short *)(param_9 + 0xa0) == 1)) {
    puVar1 = local_24;
    puVar2 = auStack_26;
    puVar3 = auStack_28;
    iVar4 = *DAT_803dd738;
    (**(code **)(iVar4 + 0x14))(param_9,*(undefined4 *)(param_10 + 0x2d0),0x10);
    FUN_8003042c((double)FLOAT_803e5870,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,*(undefined4 *)(&DAT_803265a0 + (uint)local_24[0] * 4),0,puVar1,puVar2,
                 puVar3,iVar4,in_r10);
    *(undefined4 *)(param_10 + 0x2a0) = *(undefined4 *)(&DAT_803265e0 + (uint)local_24[0] * 4);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,8);
  return 0;
}

