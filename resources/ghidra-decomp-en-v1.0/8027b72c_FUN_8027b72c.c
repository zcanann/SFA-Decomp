// Function: FUN_8027b72c
// Entry: 8027b72c
// Size: 368 bytes

undefined4
FUN_8027b72c(int *param_1,uint param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  
  if ((DAT_803de238 != '\0') && (iVar3 = (int)DAT_803de308, iVar3 < 0x80)) {
    for (piVar4 = param_1; *piVar4 != -1; piVar4 = (int *)((int)param_1 + *piVar4)) {
      if ((uint)*(ushort *)(piVar4 + 1) == (param_2 & 0xffff)) {
        (&DAT_803cbbe0)[iVar3 * 3] = piVar4;
        (&DAT_803cbbe8)[iVar3 * 3] = param_1;
        *(undefined4 *)(&DAT_803cbbe4 + iVar3 * 0xc) = param_4;
        iVar3 = piVar4[3];
        uVar1 = FUN_80283d58(param_3);
        iVar2 = FUN_802744bc(param_4,uVar1);
        if (iVar2 != 0) {
          FUN_8027b690((int)param_1 + iVar3,param_4,1,0);
        }
        FUN_8027b690((int)param_1 + piVar4[2],param_5,0,0);
        FUN_8027b690((int)param_1 + piVar4[4],param_5,4,0);
        FUN_8027b690((int)param_1 + piVar4[5],param_5,2,0);
        FUN_8027b690((int)param_1 + piVar4[6],param_5,3,0);
        if (*(short *)((int)piVar4 + 6) == 1) {
          FUN_80274798(param_2,(undefined2 *)((int)param_1 + piVar4[7]) + 2,
                       *(undefined2 *)((int)param_1 + piVar4[7]));
        }
        FUN_80283f14();
        DAT_803de308 = DAT_803de308 + 1;
        return 1;
      }
    }
  }
  return 0;
}

