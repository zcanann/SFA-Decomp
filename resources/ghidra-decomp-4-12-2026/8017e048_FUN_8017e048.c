// Function: FUN_8017e048
// Entry: 8017e048
// Size: 356 bytes

void FUN_8017e048(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  int iVar1;
  uint uVar2;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  iVar1 = FUN_8002bac4();
  dVar4 = (double)FUN_80021754((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18));
  if ((dVar4 < (double)FLOAT_803e4484) &&
     (dVar4 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_9 + 0x18)),
     dVar4 < (double)FLOAT_803e4488)) {
    uVar2 = FUN_80020078(0x90f);
    if (uVar2 == 0) {
      uVar5 = (**(code **)(*DAT_803dd6d4 + 0x7c))(0x444,0,0);
      *(undefined2 *)(iVar3 + 0x5c) = 0xffff;
      *(undefined2 *)(iVar3 + 0x5e) = 0;
      *(float *)(iVar3 + 0x60) = FLOAT_803e4460;
      FUN_800379bc(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,0x7000a,
                   param_9,iVar3 + 0x5c,in_r7,in_r8,in_r9,in_r10);
      FUN_800201ac(0x90f,1);
      *(byte *)(iVar3 + 0x5a) = *(byte *)(iVar3 + 0x5a) | 4;
    }
    else {
      FUN_8029725c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar1,
                   (uint)*(ushort *)(iVar3 + 0x38));
      FUN_80099c40((double)FLOAT_803e4460,param_9,0xff,0x28);
      uVar5 = FUN_8000bb38(param_9,0x58);
      iVar1 = *(int *)(param_9 + 0xb8);
      if ((*(ushort *)(param_9 + 6) & 0x2000) == 0) {
        if (*(int *)(param_9 + 0x54) != 0) {
          FUN_80035ff8(param_9);
        }
        *(byte *)(iVar1 + 0x5a) = *(byte *)(iVar1 + 0x5a) | 2;
      }
      else {
        FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
      }
    }
  }
  return;
}

