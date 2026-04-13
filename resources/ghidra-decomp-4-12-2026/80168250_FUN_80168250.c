// Function: FUN_80168250
// Entry: 80168250
// Size: 152 bytes

undefined4
FUN_80168250(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  bVar1 = *(char *)(param_10 + 0x27a) != '\0';
  if (bVar1) {
    if (bVar1) {
      FUN_8003042c((double)FLOAT_803e3cf8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,(int)DAT_80321050,0,param_12,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(iVar2 + 0x4a) = 4;
  }
  *(undefined4 *)(param_10 + 0x2a0) =
       *(undefined4 *)(&DAT_80321054 + (uint)*(byte *)(iVar2 + 0x4a) * 4);
  *(undefined *)(param_10 + 0x34d) = 1;
  return 0;
}

