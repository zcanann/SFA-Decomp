// Function: FUN_8029d250
// Entry: 8029d250
// Size: 516 bytes

/* WARNING: Removing unreachable block (ram,0x8029d434) */

void FUN_8029d250(void)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined8 extraout_f1;
  double dVar8;
  undefined8 in_f31;
  undefined8 uVar9;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar9 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  iVar4 = (int)uVar9;
  iVar6 = *(int *)(iVar1 + 0xb8);
  *(undefined *)(iVar4 + 0x34d) = 3;
  uVar9 = extraout_f1;
  if (*(char *)(iVar4 + 0x27a) != '\0') {
    if ((*(int *)(iVar4 + 0x2d0) == 0) || ((*(uint *)(iVar6 + 0x884) & 1) == 0)) {
      FUN_80030334((double)FLOAT_803e7ea4,iVar1,
                   (int)*(short *)(&DAT_8033366c + (uint)*(byte *)(iVar6 + 0x8a2) * 2),0);
      *(undefined4 *)(iVar4 + 0x2a0) =
           *(undefined4 *)(&DAT_8033369c + (uint)*(byte *)(iVar6 + 0x8a2) * 4);
    }
    else {
      FUN_80014aa0((double)FLOAT_803e7ed8);
      uVar2 = *(uint *)(iVar6 + 0x884);
      if ((uVar2 & 2) == 0) {
        if ((uVar2 & 4) == 0) {
          if ((uVar2 & 8) == 0) {
            iVar5 = 3;
          }
          else {
            iVar5 = 2;
          }
        }
        else {
          iVar5 = 1;
        }
      }
      else {
        iVar5 = 3;
      }
      FUN_80030334((double)*(float *)(iVar5 * 4 + -0x7fccc984),iVar1,
                   (int)*(short *)(&DAT_8033366c + iVar5 * 2),0);
      *(undefined4 *)(iVar4 + 0x2a0) = *(undefined4 *)(&DAT_8033369c + iVar5 * 4);
      *(float *)(iVar4 + 0x280) = -*(float *)(iVar6 + 0x88c);
    }
  }
  if (*(int *)(iVar4 + 0x2d0) != 0) {
    *(short *)(iVar6 + 0x478) =
         *(short *)(iVar6 + 0x478) +
         (short)(int)((float)((double)CONCAT44(0x43300000,*(uint *)(iVar6 + 0x4a4) ^ 0x80000000) -
                             DOUBLE_803e7ec0) / FLOAT_803e7fc0);
    *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
  }
  dVar8 = (double)FUN_80292b44((double)*(float *)(iVar6 + 0x888),uVar9);
  *(float *)(iVar4 + 0x280) = (float)((double)*(float *)(iVar4 + 0x280) * dVar8);
  (**(code **)(*DAT_803dca8c + 0x20))(uVar9,iVar1,iVar4,2);
  if (*(char *)(iVar4 + 0x346) == '\0') {
    uVar3 = 0;
  }
  else {
    *(code **)(iVar4 + 0x308) = FUN_802a514c;
    uVar3 = 2;
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  FUN_80286128(uVar3);
  return;
}

