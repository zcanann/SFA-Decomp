// Function: FUN_802b7bf0
// Entry: 802b7bf0
// Size: 312 bytes

/* WARNING: Removing unreachable block (ram,0x802b7d04) */

undefined4 FUN_802b7bf0(undefined8 param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 uVar2;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = *(int *)(*(int *)(param_2 + 0xb8) + 0x40c);
  if (*(int *)(param_3 + 0x2d0) != 0) {
    FUN_8003b0d0(param_2,*(int *)(param_3 + 0x2d0),*(int *)(param_2 + 0xb8) + 0x3ac,0x19);
  }
  if ((*(char *)(param_3 + 0x346) != '\0') || (*(char *)(param_3 + 0x27a) != '\0')) {
    *(undefined4 *)(param_2 + 0xc) = *(undefined4 *)(*(int *)(param_2 + 0x4c) + 8);
    *(undefined4 *)(param_2 + 0x14) = *(undefined4 *)(*(int *)(param_2 + 0x4c) + 0x10);
    *(short *)(iVar1 + 0x24) = *(short *)(iVar1 + 0x24) + 1;
    if (*(short *)(&DAT_80334f9c + (uint)*(ushort *)(iVar1 + 0x24) * 2) == -1) {
      *(undefined2 *)(iVar1 + 0x24) = 0;
    }
    FUN_80030334((double)FLOAT_803e8180,param_2,
                 (int)*(short *)(&DAT_80334f9c + (uint)*(ushort *)(iVar1 + 0x24) * 2),0);
  }
  *(undefined4 *)(param_3 + 0x2a0) =
       *(undefined4 *)(&DAT_80334fac + (uint)*(ushort *)(iVar1 + 0x24) * 4);
  (**(code **)(*DAT_803dca8c + 0x20))(param_1,param_2,param_3,1);
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return 0;
}

