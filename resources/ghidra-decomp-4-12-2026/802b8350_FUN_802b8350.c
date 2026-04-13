// Function: FUN_802b8350
// Entry: 802b8350
// Size: 312 bytes

/* WARNING: Removing unreachable block (ram,0x802b8464) */
/* WARNING: Removing unreachable block (ram,0x802b8360) */

undefined4
FUN_802b8350(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  if (*(int *)(param_10 + 0x2d0) != 0) {
    param_12 = 0x19;
    FUN_8003b1c8(param_9,*(int *)(param_10 + 0x2d0),*(int *)(param_9 + 0x5c) + 0x3ac,0x19);
  }
  if ((*(char *)(param_10 + 0x346) != '\0') || (*(char *)(param_10 + 0x27a) != '\0')) {
    *(undefined4 *)(param_9 + 6) = *(undefined4 *)(*(int *)(param_9 + 0x26) + 8);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*(int *)(param_9 + 0x26) + 0x10);
    *(short *)(iVar1 + 0x24) = *(short *)(iVar1 + 0x24) + 1;
    if (*(short *)(&DAT_80335bfc + (uint)*(ushort *)(iVar1 + 0x24) * 2) == -1) {
      *(undefined2 *)(iVar1 + 0x24) = 0;
    }
    FUN_8003042c((double)FLOAT_803e8e18,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_80335bfc + (uint)*(ushort *)(iVar1 + 0x24) * 2),0,
                 param_12,param_13,param_14,param_15,param_16);
  }
  *(undefined4 *)(param_10 + 0x2a0) =
       *(undefined4 *)(&DAT_80335c0c + (uint)*(ushort *)(iVar1 + 0x24) * 4);
  (**(code **)(*DAT_803dd70c + 0x20))(param_1,param_9,param_10,1);
  return 0;
}

