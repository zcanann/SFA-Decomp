// Function: FUN_8029d9b0
// Entry: 8029d9b0
// Size: 516 bytes

/* WARNING: Removing unreachable block (ram,0x8029db94) */
/* WARNING: Removing unreachable block (ram,0x8029d9c0) */

void FUN_8029d9b0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286840();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  iVar5 = *(int *)(iVar1 + 0xb8);
  *(undefined *)(iVar3 + 0x34d) = 3;
  dVar7 = extraout_f1;
  if (*(char *)(iVar3 + 0x27a) != '\0') {
    if ((*(int *)(iVar3 + 0x2d0) == 0) || ((*(uint *)(iVar5 + 0x884) & 1) == 0)) {
      FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   iVar1,(int)*(short *)(&DAT_803342cc + (uint)*(byte *)(iVar5 + 0x8a2) * 2),0,in_r6
                   ,in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(iVar3 + 0x2a0) =
           *(undefined4 *)(&DAT_803342fc + (uint)*(byte *)(iVar5 + 0x8a2) * 4);
    }
    else {
      FUN_80014acc((double)FLOAT_803e8b70);
      uVar2 = *(uint *)(iVar5 + 0x884);
      if ((uVar2 & 2) == 0) {
        if ((uVar2 & 4) == 0) {
          if ((uVar2 & 8) == 0) {
            iVar4 = 3;
          }
          else {
            iVar4 = 2;
          }
        }
        else {
          iVar4 = 1;
        }
      }
      else {
        iVar4 = 3;
      }
      FUN_8003042c((double)*(float *)(iVar4 * 4 + -0x7fccbd24),param_2,param_3,param_4,param_5,
                   param_6,param_7,param_8,iVar1,(int)*(short *)(&DAT_803342cc + iVar4 * 2),0,in_r6,
                   in_r7,in_r8,in_r9,in_r10);
      *(undefined4 *)(iVar3 + 0x2a0) = *(undefined4 *)(&DAT_803342fc + iVar4 * 4);
      *(float *)(iVar3 + 0x280) = -*(float *)(iVar5 + 0x88c);
    }
  }
  if (*(int *)(iVar3 + 0x2d0) != 0) {
    *(short *)(iVar5 + 0x478) =
         *(short *)(iVar5 + 0x478) +
         (short)(int)((float)((double)CONCAT44(0x43300000,*(uint *)(iVar5 + 0x4a4) ^ 0x80000000) -
                             DOUBLE_803e8b58) / FLOAT_803e8c58);
    *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
  }
  dVar6 = (double)FUN_802932a4((double)*(float *)(iVar5 + 0x888),dVar7);
  *(float *)(iVar3 + 0x280) = (float)((double)*(float *)(iVar3 + 0x280) * dVar6);
  (**(code **)(*DAT_803dd70c + 0x20))(dVar7,iVar1,iVar3,2);
  if (*(char *)(iVar3 + 0x346) != '\0') {
    *(code **)(iVar3 + 0x308) = FUN_802a58ac;
  }
  FUN_8028688c();
  return;
}

