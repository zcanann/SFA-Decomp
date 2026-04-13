// Function: FUN_8027be90
// Entry: 8027be90
// Size: 368 bytes

undefined4 FUN_8027be90(int *param_1,short param_2,undefined4 param_3,int *param_4,int *param_5)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  
  if ((DAT_803deeb8 != '\0') && (iVar3 = (int)DAT_803def88, piVar4 = param_1, iVar3 < 0x80)) {
    for (; *piVar4 != -1; piVar4 = (int *)((int)param_1 + *piVar4)) {
      if (*(short *)(piVar4 + 1) == param_2) {
        (&DAT_803cc840)[iVar3 * 3] = piVar4;
        (&DAT_803cc848)[iVar3 * 3] = param_1;
        *(int **)(&DAT_803cc844 + iVar3 * 0xc) = param_4;
        iVar3 = piVar4[3];
        uVar1 = FUN_802844bc();
        iVar2 = FUN_80274c20((short *)param_4,uVar1);
        if (iVar2 != 0) {
          FUN_8027bdf4((ushort *)((int)param_1 + iVar3),param_4,1,0);
        }
        FUN_8027bdf4((ushort *)((int)param_1 + piVar4[2]),param_5,0,0);
        FUN_8027bdf4((ushort *)((int)param_1 + piVar4[4]),param_5,4,0);
        FUN_8027bdf4((ushort *)((int)param_1 + piVar4[5]),param_5,2,0);
        FUN_8027bdf4((ushort *)((int)param_1 + piVar4[6]),param_5,3,0);
        if (*(short *)((int)piVar4 + 6) == 1) {
          FUN_80274efc(param_2,(int)((ushort *)((int)param_1 + piVar4[7]) + 2),
                       (uint)*(ushort *)((int)param_1 + piVar4[7]));
        }
        FUN_80284678();
        DAT_803def88 = DAT_803def88 + 1;
        return 1;
      }
    }
  }
  return 0;
}

