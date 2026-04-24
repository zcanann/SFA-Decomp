// Function: FUN_80160b9c
// Entry: 80160b9c
// Size: 332 bytes

void FUN_80160b9c(undefined4 param_1,undefined4 param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar1 + 0x4c);
  *(undefined *)(param_4 + 0x346) = 1;
  iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                    ((double)(float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(param_3 + 0x3fe))
                                    - DOUBLE_803e3b38),iVar1,param_4,1);
  if (iVar2 != 0) {
    *(undefined4 *)(param_4 + 0x2d0) = *(undefined4 *)(param_3 + 0x3e0);
    *(undefined *)(param_4 + 0x349) = 0;
    if (*(char *)(iVar3 + 0x2e) == -1) {
      *(undefined4 *)(param_4 + 0x2d0) = 0;
    }
    else {
      if ((int)uVar4 != 0) {
        (**(code **)(*DAT_803dd6d4 + 0x58))((int)uVar4,(int)*(short *)(iVar3 + 0x24));
      }
      *(undefined *)(param_3 + 0x405) = 1;
    }
  }
  (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3b34,iVar1,param_4,1);
  *(undefined4 *)(param_3 + 0x3e0) = *(undefined4 *)(iVar1 + 0xc0);
  *(undefined4 *)(iVar1 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,iVar1,param_4,&DAT_803ad248,&DAT_803ad230
            );
  *(undefined4 *)(iVar1 + 0xc0) = *(undefined4 *)(param_3 + 0x3e0);
  FUN_8028688c();
  return;
}

