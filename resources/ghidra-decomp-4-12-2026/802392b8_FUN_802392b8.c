// Function: FUN_802392b8
// Entry: 802392b8
// Size: 424 bytes

void FUN_802392b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  uint local_28 [2];
  undefined4 local_20;
  uint uStack_1c;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  piVar3 = *(int **)(param_9 + 0xb8);
  if ((((*piVar3 != 0) &&
       (iVar1 = FUN_80036974(param_9,(undefined4 *)0x0,(int *)0x0,local_28), iVar1 != 0)) &&
      (*(byte *)(piVar3 + 2) != 0)) &&
     (iVar1 = FUN_80080100((int *)piVar3[1],(uint)*(byte *)(piVar3 + 2),iVar1), iVar1 != -1)) {
    *piVar3 = *piVar3 - local_28[0];
    if (*(char *)(iVar4 + 0x19) == '\x02') {
      FUN_8002ad08(param_9,0x1e,200,0,0,1);
      FUN_8000bb38(param_9,0x496);
    }
    if (*piVar3 < 1) {
      iVar1 = *(int *)(param_9 + 0x4c);
      *piVar3 = 0;
      FUN_800201ac((int)*(short *)(iVar1 + 0x1e),1);
      if (*(char *)(iVar1 + 0x19) != '\0') {
        if (*(char *)(iVar1 + 0x19) == '\x02') {
          uVar2 = 0x50;
        }
        else {
          uVar2 = (uint)*(short *)(iVar1 + 0x1c);
        }
        iVar1 = *(int *)(*(int *)(param_9 + 0x4c) + 0x14);
        if (((iVar1 != 0x470ea) && (iVar1 != 0x480f5)) && ((iVar1 != 0x46710 && (iVar1 != 0x49b43)))
           ) {
          uStack_1c = uVar2 ^ 0x80000000;
          local_20 = 0x43300000;
          FUN_8009adfc((double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e80d0),
                       param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,1,1,1,0,1,0
                      );
        }
        if (*(char *)(iVar4 + 0x19) == '\x02') {
          FUN_8000bb38(param_9,0x497);
        }
      }
    }
    else {
      FUN_8000bb38(param_9,0x18);
    }
  }
  return;
}

